//! Resolves `c2pa.hash.bmff.v2`/`.v3` "exclusions" (as emitted by c2patool's
//! JSON, whose field names mirror the CDDL 1:1 — verified against a real
//! signed sample) into absolute file byte ranges, so the frontend can render
//! a "what part of this file did the manifest actually hash" coverage map.
//!
//! Every rule implemented here comes from the C2PA 2.4 spec, section 18.6
//! ("BMFF-Based Hash") and its `bmff-hash-map`/`exclusions-map` CDDL — not
//! reverse-engineered. In particular:
//! - Box header layout (4-byte size, 4-byte type, optional 8-byte largesize
//!   when size==1, optional 16-byte usertype when type=="uuid") is the
//!   standard ISO/IEC 14496-12 box header, unrelated to C2PA.
//! - `xpath` may only target container boxes with no fields of their own
//!   (spec section 18.6.2), so recursing into a box's payload as a sequence
//!   of child boxes whenever an xpath component requires it is always safe.
//! - `data`/`subset` byte offsets are relative to the box's start *including*
//!   its header (spec section 18.6.2, and confirmed against a real sample:
//!   the `/uuid` exclusion's `data.offset: 8` lands exactly on the 16-byte
//!   usertype field of a `uuid` box, right after its 8-byte base header).

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, Serialize)]
pub struct BmffBoxInfo {
    #[serde(rename = "type")]
    pub box_type: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedRange {
    pub start: u64,
    pub length: u64,
    pub xpath: String,
    #[serde(rename = "boxType")]
    pub box_type: String,
}

#[derive(Debug, Serialize)]
pub struct BmffCoverage {
    #[serde(rename = "fileSize")]
    pub file_size: u64,
    #[serde(rename = "topLevelBoxes")]
    pub top_level_boxes: Vec<BmffBoxInfo>,
    #[serde(rename = "excludedRanges")]
    pub excluded_ranges: Vec<ExcludedRange>,
    /// xpath strings that couldn't even be parsed (malformed syntax). A
    /// legitimate zero-box match (spec explicitly allows "zero or more") is
    /// NOT a warning and is not included here.
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DataMatch {
    pub offset: u64,
    pub value: String, // base64
}

#[derive(Debug, Deserialize)]
pub struct SubsetRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Deserialize)]
pub struct ExclusionInput {
    pub xpath: String,
    pub length: Option<u64>,
    pub data: Option<Vec<DataMatch>>,
    pub subset: Option<Vec<SubsetRange>>,
    pub version: Option<u8>,
    pub flags: Option<String>, // base64, 3 bytes
    pub exact: Option<bool>,
}

#[derive(Debug, Clone)]
struct RawBox {
    box_type: String,
    offset: u64,
    header_size: u64,
    size: u64,
}

impl RawBox {
    fn end(&self) -> u64 {
        self.offset + self.size
    }
    fn content_start(&self) -> u64 {
        self.offset + self.header_size
    }
}

struct PathComponent {
    name: String,
    /// 1-based index among same-named siblings, per the spec's box-naming
    /// convention ("in order of appearance"). `None` means "any" (wildcard).
    index: Option<usize>,
}

fn parse_xpath(xpath: &str) -> Option<Vec<PathComponent>> {
    let rest = xpath.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(vec![]);
    }
    rest.split('/')
        .map(|seg| {
            if let Some(open) = seg.find('[') {
                let name = seg.get(..open)?.to_string();
                let idx_str = seg.get(open + 1..)?.strip_suffix(']')?;
                let index = idx_str.parse::<usize>().ok()?;
                if index == 0 {
                    return None; // spec: 1-based, non-zero positive integer
                }
                Some(PathComponent { name, index: Some(index) })
            } else {
                Some(PathComponent { name: seg.to_string(), index: None })
            }
        })
        .collect()
}

fn read_box_header(file: &mut File, offset: u64, limit: u64) -> std::io::Result<Option<RawBox>> {
    if offset + 8 > limit {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut hdr = [0u8; 8];
    if file.read_exact(&mut hdr).is_err() {
        return Ok(None);
    }
    let mut size = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as u64;
    let box_type = String::from_utf8_lossy(&hdr[4..8]).to_string();
    let mut header_size = 8u64;

    if size == 1 {
        let mut ext = [0u8; 8];
        if file.read_exact(&mut ext).is_err() {
            return Ok(None);
        }
        size = u64::from_be_bytes(ext);
        header_size += 8;
    } else if size == 0 {
        // "extends to end of file/enclosing container" per ISO/IEC 14496-12
        size = limit - offset;
    }

    if box_type == "uuid" {
        header_size += 16; // extended usertype
    }

    if size < header_size || offset + size > limit {
        return Ok(None); // malformed / truncated — stop rather than misread
    }

    Ok(Some(RawBox { box_type, offset, header_size, size }))
}

fn list_boxes(file: &mut File, start: u64, end: u64) -> std::io::Result<Vec<RawBox>> {
    let mut boxes = Vec::new();
    let mut pos = start;
    while pos < end {
        match read_box_header(file, pos, end)? {
            Some(b) => {
                let next = b.end();
                if next <= pos {
                    break; // guard against corrupt/non-advancing box
                }
                pos = next;
                boxes.push(b);
            }
            None => break,
        }
    }
    Ok(boxes)
}

/// Walks `components` starting from `top_level`, descending into a matched
/// box's own children whenever there's a next component. Returns the boxes
/// matched by the *last* component.
fn resolve_xpath(
    file: &mut File,
    top_level: &[RawBox],
    components: &[PathComponent],
) -> std::io::Result<Vec<RawBox>> {
    let mut current_level: Vec<RawBox> = top_level.to_vec();
    for (i, comp) in components.iter().enumerate() {
        let is_last = i == components.len() - 1;
        let mut matched: Vec<RawBox> = Vec::new();
        let mut seen_of_name = 0usize;
        for b in &current_level {
            if b.box_type != comp.name {
                continue;
            }
            seen_of_name += 1;
            match comp.index {
                Some(idx) => {
                    if seen_of_name == idx {
                        matched.push(b.clone());
                    }
                }
                None => matched.push(b.clone()),
            }
        }
        if is_last {
            return Ok(matched);
        }
        let mut next_level = Vec::new();
        for b in &matched {
            next_level.extend(list_boxes(file, b.content_start(), b.end())?);
        }
        current_level = next_level;
    }
    Ok(current_level)
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn box_matches_filters(
    file: &mut File,
    b: &RawBox,
    excl: &ExclusionInput,
) -> std::io::Result<bool> {
    if let Some(len) = excl.length {
        if b.size != len {
            return Ok(false);
        }
    }

    if excl.version.is_some() || excl.flags.is_some() {
        // FullBox layout: 1-byte version + 3-byte flags, immediately after
        // the standard box header.
        file.seek(SeekFrom::Start(b.content_start()))?;
        let mut vf = [0u8; 4];
        if file.read_exact(&mut vf).is_err() {
            return Ok(false);
        }
        if let Some(v) = excl.version {
            if vf[0] != v {
                return Ok(false);
            }
        }
        if let Some(flags_b64) = &excl.flags {
            if let Some(expected) = decode_b64(flags_b64) {
                if expected.len() == 3 {
                    let actual = &vf[1..4];
                    let exact = excl.exact.unwrap_or(true);
                    let ok = if exact {
                        actual == expected.as_slice()
                    } else {
                        actual.iter().zip(expected.iter()).all(|(a, e)| (a & e) == *e)
                    };
                    if !ok {
                        return Ok(false);
                    }
                }
            }
        }
    }

    if let Some(data_matches) = &excl.data {
        for dm in data_matches {
            let Some(expected) = decode_b64(&dm.value) else { continue };
            let abs = b.offset + dm.offset;
            if abs + expected.len() as u64 > b.end() {
                return Ok(false);
            }
            let mut buf = vec![0u8; expected.len()];
            file.seek(SeekFrom::Start(abs))?;
            if file.read_exact(&mut buf).is_err() || buf != expected {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

pub fn compute_coverage(
    path: &str,
    exclusions: &[ExclusionInput],
) -> std::io::Result<BmffCoverage> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let top_level = list_boxes(&mut file, 0, file_size)?;

    let mut excluded_ranges = Vec::new();
    let mut warnings = Vec::new();

    for excl in exclusions {
        let Some(components) = parse_xpath(&excl.xpath) else {
            warnings.push(format!("could not parse xpath: {}", excl.xpath));
            continue;
        };
        let matched = resolve_xpath(&mut file, &top_level, &components)?;
        for b in matched {
            if !box_matches_filters(&mut file, &b, excl)? {
                continue;
            }
            if let Some(subsets) = &excl.subset {
                for s in subsets {
                    let start = b.offset + s.offset;
                    if start >= b.end() {
                        continue; // fully past the box — nothing to exclude
                    }
                    let length = if s.length == 0 {
                        b.end() - start // "remainder of the box"
                    } else {
                        s.length.min(b.end() - start) // clamp to box end
                    };
                    excluded_ranges.push(ExcludedRange {
                        start,
                        length,
                        xpath: excl.xpath.clone(),
                        box_type: b.box_type.clone(),
                    });
                }
            } else {
                excluded_ranges.push(ExcludedRange {
                    start: b.offset,
                    length: b.size,
                    xpath: excl.xpath.clone(),
                    box_type: b.box_type.clone(),
                });
            }
        }
    }

    let top_level_boxes = top_level
        .iter()
        .map(|b| BmffBoxInfo { box_type: b.box_type.clone(), offset: b.offset, size: b.size })
        .collect();

    Ok(BmffCoverage { file_size, top_level_boxes, excluded_ranges, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Real signed asset from c2pa-org/public-testfiles — this exact file is
    /// the source of the spec's own `/uuid`, `/ftyp`, `/mfra` example
    /// (section 18.6.3). Its `c2pa.hash.bmff.v2` assertion is:
    ///   exclusions: [
    ///     { xpath: "/uuid", data: [{ offset: 8, value: <16-byte UUID> }] },
    ///     { xpath: "/ftyp" },
    ///     { xpath: "/mfra" },
    ///   ]
    fn sample_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../samples/truepic-zoetrope.mp4")
    }

    #[test]
    fn resolves_real_bmff_v2_exclusions() {
        let sample = sample_path();
        if !sample.is_file() {
            eprintln!("skipping: sample not present at {}", sample.display());
            return;
        }

        let exclusions = vec![
            ExclusionInput {
                xpath: "/uuid".to_string(),
                length: None,
                data: Some(vec![DataMatch {
                    offset: 8,
                    value: "2P7D1hsOSDySl1goh37EgQ==".to_string(),
                }]),
                subset: None,
                version: None,
                flags: None,
                exact: None,
            },
            ExclusionInput {
                xpath: "/ftyp".to_string(),
                length: None,
                data: None,
                subset: None,
                version: None,
                flags: None,
                exact: None,
            },
            ExclusionInput {
                xpath: "/mfra".to_string(),
                length: None,
                data: None,
                subset: None,
                version: None,
                flags: None,
                exact: None,
            },
        ];

        let coverage =
            compute_coverage(sample.to_str().unwrap(), &exclusions).expect("should parse boxes");

        assert!(coverage.warnings.is_empty(), "warnings: {:?}", coverage.warnings);

        // ftyp is always the first box in this file, at offset 0, size 0x18.
        let ftyp = coverage
            .top_level_boxes
            .iter()
            .find(|b| b.box_type == "ftyp")
            .expect("ftyp box present");
        assert_eq!(ftyp.offset, 0);
        assert_eq!(ftyp.size, 0x18);

        // uuid box follows immediately at offset 24, verified via hexdump.
        let uuid = coverage
            .top_level_boxes
            .iter()
            .find(|b| b.box_type == "uuid")
            .expect("uuid box present");
        assert_eq!(uuid.offset, 24);

        let uuid_excl = coverage
            .excluded_ranges
            .iter()
            .find(|r| r.box_type == "uuid")
            .expect("uuid exclusion resolved (data match must have passed)");
        assert_eq!(uuid_excl.start, uuid.offset);
        assert_eq!(uuid_excl.length, uuid.size);

        let ftyp_excl = coverage
            .excluded_ranges
            .iter()
            .find(|r| r.box_type == "ftyp")
            .expect("ftyp exclusion resolved");
        assert_eq!(ftyp_excl.start, 0);
        assert_eq!(ftyp_excl.length, 0x18);

        // This file isn't fragmented, so no top-level `mfra` box exists —
        // per spec that's a valid "zero boxes matched", not a warning.
        assert!(!coverage.top_level_boxes.iter().any(|b| b.box_type == "mfra"));
        assert!(!coverage.excluded_ranges.iter().any(|r| r.box_type == "mfra"));

        // Sanity: total top-level box span should reach the end of file.
        let last = coverage.top_level_boxes.last().unwrap();
        assert_eq!(last.offset + last.size, coverage.file_size);
    }
}
