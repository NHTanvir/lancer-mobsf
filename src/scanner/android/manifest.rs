// AXML binary manifest parser

//! Parses Android's binary XML format (AXML / ARSC chunk format) as found in
//! `AndroidManifest.xml` inside an APK, then extracts security-relevant
//! fields used by the scanner.
//!
//! # Format summary
//! ```text
//! File header  : type(2)=0x0003, hdr_size(2), file_size(4)
//! STRING_POOL  : type(2)=0x0001, hdr_size(2), chunk_size(4),
//!                string_count(4), style_count(4), flags(4),
//!                strings_start(4), styles_start(4),
//!                [string_count × u32 offsets],
//!                [string data]
//! XML events   : type(2), hdr_size(2), chunk_size(4), line(4), comment(4), [payload…]
//!   START_NS   : 0x0100
//!   END_NS     : 0x0101
//!   START_ELEM : 0x0102
//!   END_ELEM   : 0x0103
//! ```
//! All integers are little-endian.

use anyhow::{bail, Result};

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedManifest {
    pub package: String,
    pub version_name: String,
    pub version_code: Option<i32>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub debuggable: bool,
    pub allow_backup: bool,
    pub uses_cleartext_traffic: bool,
    pub network_security_config: Option<String>,
    pub permissions: Vec<String>,
    pub activities: Vec<Component>,
    pub services: Vec<Component>,
    pub receivers: Vec<Component>,
    pub providers: Vec<Component>,
    pub intent_filters: Vec<IntentFilter>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Component {
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_hosts: Vec<String>,
    pub data_paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// Internal byte-reading helpers (no byteorder crate needed)
// ---------------------------------------------------------------------------

#[inline]
fn read_u16(buf: &[u8], pos: usize) -> Result<u16> {
    buf.get(pos..pos + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| anyhow::anyhow!("read_u16 OOB at {pos}"))
}

#[inline]
fn read_u32(buf: &[u8], pos: usize) -> Result<u32> {
    buf.get(pos..pos + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| anyhow::anyhow!("read_u32 OOB at {pos}"))
}

// ---------------------------------------------------------------------------
// String-pool parser
// ---------------------------------------------------------------------------

const FLAG_UTF8: u32 = 1 << 8;

/// Parse an AXML string pool chunk starting at `pool_start`.
fn parse_string_pool(buf: &[u8], pool_start: usize) -> Result<Vec<String>> {
    // Common chunk header: type(2) hdr_size(2) chunk_size(4)  → 8 bytes
    // String pool header (after the 8-byte common part):
    //   string_count(4) style_count(4) flags(4) strings_start(4) styles_start(4) → 20 bytes
    // Total fixed header = 28 bytes.
    if pool_start + 28 > buf.len() {
        bail!("string pool header OOB");
    }
    let hdr_size    = read_u16(buf, pool_start + 2)? as usize;
    let chunk_size  = read_u32(buf, pool_start + 4)? as usize;
    let str_count   = read_u32(buf, pool_start + 8)?  as usize;
    let flags       = read_u32(buf, pool_start + 16)?;
    let strings_off = read_u32(buf, pool_start + 20)? as usize; // offset from pool_start

    let is_utf8 = (flags & FLAG_UTF8) != 0;

    let pool_end    = pool_start + chunk_size;
    if pool_end > buf.len() {
        bail!("string pool chunk exceeds buffer");
    }

    // Offset table starts right after the fixed pool header.
    let offsets_base = pool_start + hdr_size;
    // String data starts at pool_start + strings_off.
    let data_base    = pool_start + strings_off;

    let mut strings = Vec::with_capacity(str_count);
    for i in 0..str_count {
        let off_pos = offsets_base + i * 4;
        let offset  = read_u32(buf, off_pos)? as usize;
        let s_pos   = data_base + offset;
        let s = if is_utf8 {
            read_utf8_string(buf, s_pos, pool_end)
        } else {
            read_utf16_string(buf, s_pos, pool_end)
        };
        strings.push(s);
    }
    Ok(strings)
}

/// Variable-length integer used for character/byte counts in UTF-8 strings.
fn axml_len(buf: &[u8], pos: usize, limit: usize) -> (usize, usize) {
    if pos >= limit { return (0, pos); }
    let b0 = buf[pos] as usize;
    if b0 & 0x80 != 0 && pos + 1 < limit {
        let b1 = buf[pos + 1] as usize;
        ((b0 & 0x7F) << 8 | b1, pos + 2)
    } else {
        (b0, pos + 1)
    }
}

fn read_utf8_string(buf: &[u8], pos: usize, limit: usize) -> String {
    let (_clen, pos) = axml_len(buf, pos, limit);  // char length (skip)
    let (blen, pos) = axml_len(buf, pos, limit);   // byte length
    if pos + blen > limit { return String::new(); }
    std::str::from_utf8(&buf[pos..pos + blen])
        .unwrap_or("")
        .to_string()
}

fn read_utf16_string(buf: &[u8], pos: usize, limit: usize) -> String {
    if pos + 2 > limit { return String::new(); }
    let first = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
    let (char_count, pos) = if first & 0x8000 != 0 {
        if pos + 4 > limit { return String::new(); }
        let lo = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        ((first & 0x7FFF) << 16 | lo, pos + 4)
    } else {
        (first, pos + 2)
    };

    let byte_len = char_count * 2;
    let safe_end = (pos + byte_len).min(limit);
    let safe_count = (safe_end - pos) / 2;
    let units: Vec<u16> = (0..safe_count)
        .map(|j| u16::from_le_bytes([buf[pos + j * 2], buf[pos + j * 2 + 1]]))
        .collect();
    String::from_utf16_lossy(&units).to_string()
}

// ---------------------------------------------------------------------------
// Attribute value resolution
// ---------------------------------------------------------------------------

const TYPE_STRING:      u8 = 0x03;
const TYPE_INT_DEC:     u8 = 0x10;
const TYPE_INT_HEX:     u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

fn attr_str(pool: &[String], raw_idx: u32, vtype: u8, vdata: u32) -> String {
    match vtype {
        TYPE_STRING => pool.get(vdata as usize).cloned().unwrap_or_default(),
        TYPE_INT_BOOLEAN => if vdata == 0 { "false" } else { "true" }.to_string(),
        TYPE_INT_HEX => format!("0x{:x}", vdata),
        TYPE_INT_DEC => format!("{}", vdata as i32),
        _ => {
            if raw_idx != 0xFFFF_FFFF {
                pool.get(raw_idx as usize).cloned().unwrap_or_default()
            } else {
                format!("{}", vdata)
            }
        }
    }
}

fn attr_bool(vtype: u8, vdata: u32) -> bool {
    match vtype {
        TYPE_INT_BOOLEAN | TYPE_INT_DEC | TYPE_INT_HEX => vdata != 0,
        _ => false,
    }
}

fn attr_i32(vtype: u8, vdata: u32) -> Option<i32> {
    match vtype {
        TYPE_INT_DEC | TYPE_INT_HEX | TYPE_INT_BOOLEAN => Some(vdata as i32),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Chunk constants
// ---------------------------------------------------------------------------

const CHUNK_STRING_POOL: u16 = 0x0001;
const CHUNK_XML_NS_START: u16 = 0x0100;
const CHUNK_XML_NS_END:   u16 = 0x0101;
const CHUNK_XML_START:    u16 = 0x0102;
const CHUNK_XML_END:      u16 = 0x0103;

// ---------------------------------------------------------------------------
// Internal parsed-attribute type
// ---------------------------------------------------------------------------

struct RawAttr {
    name:    String,
    raw_idx: u32,
    vtype:   u8,
    vdata:   u32,
}

struct StartElem {
    name:  String,
    attrs: Vec<RawAttr>,
    depth: usize,
}

// ---------------------------------------------------------------------------
// AXML walker
// ---------------------------------------------------------------------------

fn walk_axml(buf: &[u8], pool: &[String]) -> Result<Vec<StartElem>> {
    let mut pos   = 0usize;
    let mut elems = Vec::new();
    let mut depth = 0usize;

    // Skip RES_XML_TYPE file header if present (type == 0x0003).
    if buf.len() >= 8 {
        let t = read_u16(buf, 0).unwrap_or(0);
        if t == 0x0003 { pos = 8; }
    }

    while pos + 8 <= buf.len() {
        let chunk_type = match read_u16(buf, pos) { Ok(v) => v, Err(_) => break };
        let hdr_size   = match read_u16(buf, pos + 2) { Ok(v) => v as usize, Err(_) => break };
        let chunk_size = match read_u32(buf, pos + 4) { Ok(v) => v as usize, Err(_) => break };

        if chunk_size == 0 { break; }
        if pos + chunk_size > buf.len() { break; }

        match chunk_type {
            CHUNK_STRING_POOL | CHUNK_XML_NS_START | CHUNK_XML_NS_END => { /* skip / already parsed */ }

            CHUNK_XML_START => {
                // Element header (offsets from chunk start):
                //  0: type(2) hdr_size(2) chunk_size(4)
                //  8: line(4) comment(4)
                // 16: ns(4) name_idx(4)
                // 24: attr_start(2) attr_size(2) attr_count(2) id_idx(2) class_idx(2) style_idx(2)
                // hdr_size is typically 36 (0x24).
                if pos + 32 > buf.len() { break; }

                let name_idx   = read_u32(buf, pos + 20).unwrap_or(0xFFFF_FFFF) as usize;
                let attr_start = read_u16(buf, pos + 24).unwrap_or(0) as usize; // relative to after-hdr
                let attr_size  = read_u16(buf, pos + 26).unwrap_or(20) as usize;
                let attr_count = read_u16(buf, pos + 28).unwrap_or(0) as usize;

                let elem_name = pool.get(name_idx).cloned().unwrap_or_default();

                // Attributes start at: pos + hdr_size + attr_start
                let attrs_base = pos + hdr_size + attr_start;
                let real_attr_size = if attr_size == 0 { 20 } else { attr_size };

                let mut attrs = Vec::with_capacity(attr_count);
                for ai in 0..attr_count {
                    let a = attrs_base + ai * real_attr_size;
                    if a + 20 > buf.len() { break; }
                    // Attr layout: ns(4) name(4) raw_value(4) val_size(2) val_res0(1) val_type(1) val_data(4)
                    let name_i  = read_u32(buf, a + 4).unwrap_or(0xFFFF_FFFF) as usize;
                    let raw_idx = read_u32(buf, a + 8).unwrap_or(0xFFFF_FFFF);
                    let vtype   = buf[a + 15];
                    let vdata   = read_u32(buf, a + 16).unwrap_or(0);
                    let aname   = pool.get(name_i).cloned().unwrap_or_default();
                    attrs.push(RawAttr { name: aname, raw_idx, vtype, vdata });
                }

                elems.push(StartElem { name: elem_name, attrs, depth });
                depth += 1;
            }

            CHUNK_XML_END => {
                if depth > 0 { depth -= 1; }
            }

            _ => { /* unknown chunk – skip */ }
        }

        pos += chunk_size;
    }

    Ok(elems)
}

// ---------------------------------------------------------------------------
// String-pool locator
// ---------------------------------------------------------------------------

fn locate_string_pool(buf: &[u8]) -> Result<Vec<String>> {
    let mut pos = 0usize;
    // Skip file-level header if present.
    if buf.len() >= 8 && read_u16(buf, 0)? == 0x0003 {
        pos = 8;
    }
    while pos + 8 <= buf.len() {
        let ctype = read_u16(buf, pos).unwrap_or(0);
        let csize = read_u32(buf, pos + 4).unwrap_or(0) as usize;
        if ctype == CHUNK_STRING_POOL {
            return parse_string_pool(buf, pos);
        }
        if csize == 0 { break; }
        pos += csize;
    }
    Ok(Vec::new()) // return empty rather than hard error
}

// ---------------------------------------------------------------------------
// Build-manifest logic
// ---------------------------------------------------------------------------

/// Context tag for the element stack.
enum ElemCtx {
    Activity(Component),
    Service(Component),
    Receiver(Component),
    Provider(Component),
    IntentFilter(IntentFilter),
    Other,
}

/// Parse a binary AXML `AndroidManifest.xml` into a [`ParsedManifest`].
pub fn parse_manifest(axml_bytes: &[u8]) -> Result<ParsedManifest> {
    if axml_bytes.len() < 8 {
        bail!("AXML buffer too short ({} bytes)", axml_bytes.len());
    }

    let pool  = locate_string_pool(axml_bytes)?;
    let elems = walk_axml(axml_bytes, &pool)?;

    let mut m = ParsedManifest {
        package: String::new(),
        version_name: String::new(),
        version_code: None,
        min_sdk: None,
        target_sdk: None,
        debuggable: false,
        allow_backup: true,          // Android platform default
        uses_cleartext_traffic: false,
        network_security_config: None,
        permissions: Vec::new(),
        activities: Vec::new(),
        services: Vec::new(),
        receivers: Vec::new(),
        providers: Vec::new(),
        intent_filters: Vec::new(),
    };

    // Stack entries: (context, open_depth)
    let mut stack: Vec<(ElemCtx, usize)> = Vec::new();

    for elem in &elems {
        // Close any context whose open_depth >= this elem's depth.
        flush_closed_contexts(elem.depth, &mut stack, &mut m);

        match elem.name.as_str() {
            "manifest" => {
                for a in &elem.attrs {
                    match a.name.as_str() {
                        "package" => {
                            m.package = attr_str(&pool, a.raw_idx, a.vtype, a.vdata);
                        }
                        "versionName" => {
                            m.version_name = attr_str(&pool, a.raw_idx, a.vtype, a.vdata);
                        }
                        "versionCode" => {
                            m.version_code = attr_i32(a.vtype, a.vdata);
                        }
                        _ => {}
                    }
                }
            }

            "uses-sdk" => {
                for a in &elem.attrs {
                    match a.name.as_str() {
                        "minSdkVersion"    => { m.min_sdk    = attr_i32(a.vtype, a.vdata); }
                        "targetSdkVersion" => { m.target_sdk = attr_i32(a.vtype, a.vdata); }
                        _ => {}
                    }
                }
            }

            "application" => {
                for a in &elem.attrs {
                    match a.name.as_str() {
                        "debuggable" => {
                            m.debuggable = attr_bool(a.vtype, a.vdata);
                        }
                        "allowBackup" => {
                            m.allow_backup = attr_bool(a.vtype, a.vdata);
                        }
                        "usesCleartextTraffic" => {
                            m.uses_cleartext_traffic = attr_bool(a.vtype, a.vdata);
                        }
                        "networkSecurityConfig" => {
                            let v = attr_str(&pool, a.raw_idx, a.vtype, a.vdata);
                            if !v.is_empty() { m.network_security_config = Some(v); }
                        }
                        _ => {}
                    }
                }
            }

            "uses-permission" | "uses-permission-sdk-23" => {
                let name = find_attr_str(&pool, &elem.attrs, "name");
                if !name.is_empty() { m.permissions.push(name); }
            }

            "activity" | "activity-alias" => {
                stack.push((ElemCtx::Activity(parse_component(&pool, &elem.attrs)), elem.depth));
            }
            "service" => {
                stack.push((ElemCtx::Service(parse_component(&pool, &elem.attrs)), elem.depth));
            }
            "receiver" => {
                stack.push((ElemCtx::Receiver(parse_component(&pool, &elem.attrs)), elem.depth));
            }
            "provider" => {
                stack.push((ElemCtx::Provider(parse_component(&pool, &elem.attrs)), elem.depth));
            }

            "intent-filter" => {
                stack.push((ElemCtx::IntentFilter(IntentFilter::default()), elem.depth));
            }

            "action" => {
                let name = find_attr_str(&pool, &elem.attrs, "name");
                if !name.is_empty() {
                    if let Some(f) = innermost_filter_mut(&mut stack) {
                        f.actions.push(name);
                    }
                }
            }
            "category" => {
                let name = find_attr_str(&pool, &elem.attrs, "name");
                if !name.is_empty() {
                    if let Some(f) = innermost_filter_mut(&mut stack) {
                        f.categories.push(name);
                    }
                }
            }
            "data" => {
                if let Some(f) = innermost_filter_mut(&mut stack) {
                    let s = find_attr_str(&pool, &elem.attrs, "scheme");
                    let h = find_attr_str(&pool, &elem.attrs, "host");
                    let p = find_attr_str(&pool, &elem.attrs, "path");
                    if !s.is_empty() { f.data_schemes.push(s); }
                    if !h.is_empty() { f.data_hosts.push(h);   }
                    if !p.is_empty() { f.data_paths.push(p);   }
                }
            }

            _ => {
                stack.push((ElemCtx::Other, elem.depth));
            }
        }
    }

    // Drain remaining stack in LIFO order.
    while let Some((ctx, _)) = stack.pop() {
        commit(ctx, &mut stack, &mut m);
    }

    Ok(m)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_component(pool: &[String], attrs: &[RawAttr]) -> Component {
    let mut c = Component { name: String::new(), exported: None, permission: None, intent_filters: Vec::new() };
    for a in attrs {
        match a.name.as_str() {
            "name"       => { c.name       = attr_str(pool, a.raw_idx, a.vtype, a.vdata); }
            "exported"   => { c.exported   = Some(attr_bool(a.vtype, a.vdata)); }
            "permission" => {
                let v = attr_str(pool, a.raw_idx, a.vtype, a.vdata);
                if !v.is_empty() { c.permission = Some(v); }
            }
            _ => {}
        }
    }
    c
}

fn find_attr_str(pool: &[String], attrs: &[RawAttr], key: &str) -> String {
    attrs.iter()
         .find(|a| a.name == key)
         .map(|a| attr_str(pool, a.raw_idx, a.vtype, a.vdata))
         .unwrap_or_default()
}

fn innermost_filter_mut(stack: &mut Vec<(ElemCtx, usize)>) -> Option<&mut IntentFilter> {
    for (ctx, _) in stack.iter_mut().rev() {
        if let ElemCtx::IntentFilter(ref mut f) = ctx {
            return Some(f);
        }
    }
    None
}

/// Close all stack entries whose open_depth >= `current_depth`.
fn flush_closed_contexts(current_depth: usize, stack: &mut Vec<(ElemCtx, usize)>, m: &mut ParsedManifest) {
    while stack.last().map_or(false, |(_, d)| *d >= current_depth) {
        let (ctx, _) = stack.pop().unwrap();
        commit(ctx, stack, m);
    }
}

/// Commit a finished context to the manifest (or attach to parent component).
fn commit(ctx: ElemCtx, stack: &mut Vec<(ElemCtx, usize)>, m: &mut ParsedManifest) {
    match ctx {
        ElemCtx::Activity(c) => m.activities.push(c),
        ElemCtx::Service(c)  => m.services.push(c),
        ElemCtx::Receiver(c) => m.receivers.push(c),
        ElemCtx::Provider(c) => m.providers.push(c),
        ElemCtx::IntentFilter(f) => {
            // Attach to the nearest enclosing component on the stack.
            let mut attached = false;
            for (ctx2, _) in stack.iter_mut().rev() {
                match ctx2 {
                    ElemCtx::Activity(ref mut c)
                    | ElemCtx::Service(ref mut c)
                    | ElemCtx::Receiver(ref mut c)
                    | ElemCtx::Provider(ref mut c) => {
                        c.intent_filters.push(f.clone());
                        attached = true;
                        break;
                    }
                    _ => {}
                }
            }
            if !attached {
                m.intent_filters.push(f);
            }
        }
        ElemCtx::Other => {}
    }
}
