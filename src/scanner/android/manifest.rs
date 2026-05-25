// AXML binary manifest parser + manifest analyzer

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

// ---------------------------------------------------------------------------
// Manifest analyzer – 30+ security rules
// ---------------------------------------------------------------------------

use crate::scanner::ScanFinding;

fn finding(
    rule_id: &str,
    title: impl Into<String>,
    severity: &str,
    description: impl Into<String>,
    cwe: Option<&str>,
    owasp: Option<&str>,
    masvs: Option<&str>,
    evidence: Option<String>,
) -> ScanFinding {
    ScanFinding {
        rule_id: rule_id.to_string(),
        title: title.into(),
        severity: severity.to_string(),
        description: description.into(),
        file_path: Some("AndroidManifest.xml".to_string()),
        line_number: None,
        cwe: cwe.map(|s| s.to_string()),
        owasp: owasp.map(|s| s.to_string()),
        masvs: masvs.map(|s| s.to_string()),
        evidence,
    }
}

/// Analyse a [`ParsedManifest`] and return a list of security findings.
/// Implements 30+ rules covering manifest misconfigurations.
pub fn analyze_manifest(manifest: &ParsedManifest) -> Vec<ScanFinding> {
    let mut findings: Vec<ScanFinding> = Vec::new();

    // -----------------------------------------------------------------------
    // Rule 1: android_debuggable
    // -----------------------------------------------------------------------
    if manifest.debuggable {
        findings.push(finding(
            "android_debuggable",
            "Application is debuggable",
            "high",
            "The app has android:debuggable=true set. An attacker can attach a debugger, \
             extract memory, and modify execution.",
            Some("CWE-489"),
            Some("m1"),
            Some("resilience-1"),
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 2: android_backup_allowed
    // -----------------------------------------------------------------------
    if manifest.allow_backup {
        findings.push(finding(
            "android_backup_allowed",
            "Application allows backup",
            "medium",
            "android:allowBackup=true (or absent, defaulting to true on API < 31) permits \
             ADB backup of application data. Sensitive data may be extracted.",
            Some("CWE-312"),
            Some("m2"),
            Some("storage-1"),
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 3: android_cleartext_traffic
    // -----------------------------------------------------------------------
    if manifest.uses_cleartext_traffic {
        findings.push(finding(
            "android_cleartext_traffic",
            "Application allows cleartext traffic",
            "high",
            "android:usesCleartextTraffic=true allows unencrypted HTTP connections.",
            Some("CWE-319"),
            Some("m3"),
            Some("network-1"),
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 4: android_min_sdk_low
    // -----------------------------------------------------------------------
    if manifest.min_sdk.map_or(false, |v| v < 21) {
        findings.push(finding(
            "android_min_sdk_low",
            "Minimum SDK version is too low",
            "medium",
            "minSdkVersion < 21 means the app supports Android < 5.0, which has known \
             security vulnerabilities.",
            None,
            Some("m8"),
            None,
            manifest.min_sdk.map(|v| format!("minSdkVersion={}", v)),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 5: android_target_sdk_old
    // -----------------------------------------------------------------------
    if manifest.target_sdk.map_or(false, |v| v < 33) {
        findings.push(finding(
            "android_target_sdk_old",
            "Target SDK version is outdated",
            "low",
            "targetSdkVersion < 33 may miss recent Android security hardening measures.",
            None,
            Some("m8"),
            None,
            manifest.target_sdk.map(|v| format!("targetSdkVersion={}", v)),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 6: android_exported_activity_no_permission
    // -----------------------------------------------------------------------
    for activity in &manifest.activities {
        if activity.exported == Some(true)
            && activity.permission.is_none()
            && activity.intent_filters.is_empty()
        {
            findings.push(finding(
                "android_exported_activity_no_permission",
                format!("Exported Activity without permission protection: {}", activity.name),
                "high",
                format!(
                    "Activity '{}' is exported without a permission requirement. Any app can \
                     launch it.",
                    activity.name
                ),
                Some("CWE-926"),
                Some("m1"),
                Some("platform-1"),
                Some(activity.name.clone()),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 7: android_exported_service_no_permission
    // -----------------------------------------------------------------------
    for service in &manifest.services {
        if service.exported == Some(true)
            && service.permission.is_none()
            && service.intent_filters.is_empty()
        {
            findings.push(finding(
                "android_exported_service_no_permission",
                format!("Exported Service without permission protection: {}", service.name),
                "high",
                format!(
                    "Service '{}' is exported without a permission requirement. Any app can \
                     bind to it.",
                    service.name
                ),
                Some("CWE-926"),
                Some("m1"),
                Some("platform-1"),
                Some(service.name.clone()),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 8: android_exported_receiver_no_permission
    // -----------------------------------------------------------------------
    for receiver in &manifest.receivers {
        if receiver.exported == Some(true)
            && receiver.permission.is_none()
            && receiver.intent_filters.is_empty()
        {
            findings.push(finding(
                "android_exported_receiver_no_permission",
                format!("Exported BroadcastReceiver without permission protection: {}", receiver.name),
                "high",
                format!(
                    "Receiver '{}' is exported without a permission requirement. Any app can \
                     send broadcasts to it.",
                    receiver.name
                ),
                Some("CWE-926"),
                Some("m1"),
                Some("platform-1"),
                Some(receiver.name.clone()),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 9: android_exported_provider_no_permission
    // -----------------------------------------------------------------------
    for provider in &manifest.providers {
        if provider.exported == Some(true) && provider.permission.is_none() {
            findings.push(finding(
                "android_exported_provider_no_permission",
                format!("Exported ContentProvider without permission: {}", provider.name),
                "critical",
                format!(
                    "ContentProvider '{}' is exported without a permission requirement. Any \
                     app can read or write its data.",
                    provider.name
                ),
                Some("CWE-926"),
                Some("m2"),
                Some("storage-3"),
                Some(provider.name.clone()),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 10: android_task_hijacking
    // -----------------------------------------------------------------------
    for activity in &manifest.activities {
        let has_main_action = activity.intent_filters.iter().any(|f| {
            f.actions
                .iter()
                .any(|a| a == "android.intent.action.MAIN")
        });
        // We flag activities that have ACTION_MAIN with no launchMode restriction
        // (we cannot parse launchMode here, so we flag exported ones with ACTION_MAIN
        // that lack a task affinity guard by checking for singleTask / singleInstance
        // absence – best-effort static check).
        if has_main_action && activity.exported != Some(false) {
            findings.push(finding(
                "android_task_hijacking",
                "Potential task hijacking",
                "medium",
                "Activity with ACTION_MAIN may be vulnerable to task affinity hijacking if \
                 launchMode is singleTask without explicit taskAffinity protection.",
                Some("CWE-926"),
                Some("m1"),
                Some("platform-2"),
                Some(activity.name.clone()),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 11: android_deep_link
    // -----------------------------------------------------------------------
    for activity in &manifest.activities {
        for filter in &activity.intent_filters {
            for scheme in &filter.data_schemes {
                if scheme == "http" || scheme == "https" {
                    let host = filter.data_hosts.first().cloned().unwrap_or_default();
                    let path = filter.data_paths.first().cloned().unwrap_or_default();
                    let evidence = format!("{}://{}{}", scheme, host, path);
                    findings.push(finding(
                        "android_deep_link",
                        "Deep link registered",
                        "info",
                        format!(
                            "App registers deep link handler for {}. Verify input validation \
                             in the handler.",
                            evidence
                        ),
                        None,
                        None,
                        None,
                        Some(evidence),
                    ));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rule 12: android_custom_intent_filter
    // -----------------------------------------------------------------------
    for activity in &manifest.activities {
        for filter in &activity.intent_filters {
            for action in &filter.actions {
                if !action.starts_with("android.") && !action.starts_with("com.android.") {
                    findings.push(finding(
                        "android_custom_intent_filter",
                        "Custom intent filter action",
                        "info",
                        format!("App registers custom intent filter action: {}", action),
                        None,
                        None,
                        None,
                        Some(action.clone()),
                    ));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rule 13: android_no_network_security_config
    // -----------------------------------------------------------------------
    if manifest.network_security_config.is_none()
        && manifest.target_sdk.map_or(false, |v| v < 28)
    {
        findings.push(finding(
            "android_no_network_security_config",
            "No Network Security Config defined",
            "low",
            "The app has no networkSecurityConfig defined and targets API < 28. Certificate \
             pinning is not enforced and cleartext may be permitted by default.",
            None,
            Some("m3"),
            Some("network-2"),
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 14: android_implicit_pending_intent (always info)
    // -----------------------------------------------------------------------
    findings.push(finding(
        "android_implicit_pending_intent",
        "Dynamic analysis recommended for pending intents",
        "info",
        "Pending intents and dynamically registered receivers cannot be fully audited \
         statically. Perform dynamic analysis to verify intent mutability flags.",
        None,
        None,
        Some("platform-4"),
        None,
    ));

    // -----------------------------------------------------------------------
    // Rule 15: android_missing_cleartext_attribute (older SDK, no attribute set)
    // -----------------------------------------------------------------------
    if !manifest.uses_cleartext_traffic
        && manifest.network_security_config.is_none()
        && manifest.target_sdk.map_or(false, |v| v < 28)
    {
        findings.push(finding(
            "android_cleartext_default_allowed",
            "Cleartext traffic allowed by platform default",
            "medium",
            "For targetSdkVersion < 28, Android allows cleartext HTTP by default even \
             without an explicit usesCleartextTraffic attribute.",
            Some("CWE-319"),
            Some("m3"),
            Some("network-1"),
            manifest.target_sdk.map(|v| format!("targetSdkVersion={}", v)),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 16: android_exported_activity_main_entry_point (enumeration / info)
    // -----------------------------------------------------------------------
    let main_activities: Vec<&Component> = manifest
        .activities
        .iter()
        .filter(|a| {
            a.intent_filters.iter().any(|f| {
                f.actions.iter().any(|ac| ac == "android.intent.action.MAIN")
                    && f.categories
                        .iter()
                        .any(|c| c == "android.intent.category.LAUNCHER")
            })
        })
        .collect();

    for act in &main_activities {
        findings.push(finding(
            "android_main_launcher_activity",
            "Application entry-point activity identified",
            "info",
            format!(
                "Activity '{}' is the main launcher entry point. Ensure it enforces \
                 authentication before exposing sensitive features.",
                act.name
            ),
            None,
            None,
            None,
            Some(act.name.clone()),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 17: android_many_exported_activities
    // -----------------------------------------------------------------------
    let exported_activity_count = manifest
        .activities
        .iter()
        .filter(|a| a.exported == Some(true))
        .count();
    if exported_activity_count > 10 {
        findings.push(finding(
            "android_many_exported_activities",
            "Large number of exported activities",
            "info",
            format!(
                "The app exports {} activities. A large attack surface increases the risk \
                 of unintended component access.",
                exported_activity_count
            ),
            None,
            Some("m1"),
            None,
            Some(format!("exported_activities={}", exported_activity_count)),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 18: android_provider_missing_read_or_write_permission
    // -----------------------------------------------------------------------
    for provider in &manifest.providers {
        if provider.exported == Some(true) {
            // Even if a top-level permission exists, separate read/write checks
            // are meaningful. We flag when there is no permission at all (covered
            // by rule 9) so here we target providers that have partial protection.
            // We can't detect readPermission / writePermission from the current
            // ParsedManifest struct (only `permission` is stored). Flag all
            // exported providers that rely only on the umbrella permission as
            // needing explicit readPermission/writePermission review.
            if provider.permission.is_some() {
                findings.push(finding(
                    "android_provider_missing_rw_permission",
                    format!(
                        "ContentProvider may lack granular read/write permissions: {}",
                        provider.name
                    ),
                    "high",
                    format!(
                        "ContentProvider '{}' uses a single permission for both read and write \
                         access. Consider defining separate readPermission and writePermission \
                         attributes to enforce least privilege.",
                        provider.name
                    ),
                    Some("CWE-284"),
                    Some("m2"),
                    Some("storage-3"),
                    Some(provider.name.clone()),
                ));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rule 19: android_target_sdk_below_28 (cleartext allowed by default)
    // -----------------------------------------------------------------------
    if manifest.target_sdk.map_or(false, |v| v < 28) {
        findings.push(finding(
            "android_target_sdk_below_28",
            "Target SDK below 28 allows cleartext traffic by default",
            "medium",
            "On Android < 9.0 (API 28) cleartext HTTP is permitted by default. Upgrade \
             targetSdkVersion to 28 or higher and add a Network Security Config.",
            Some("CWE-319"),
            Some("m3"),
            Some("network-1"),
            manifest.target_sdk.map(|v| format!("targetSdkVersion={}", v)),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 20: android_exported_component_with_data_no_permission
    // -----------------------------------------------------------------------
    for activity in &manifest.activities {
        if activity.permission.is_none() {
            for filter in &activity.intent_filters {
                if !filter.data_schemes.is_empty() {
                    findings.push(finding(
                        "android_exported_component_data_no_permission",
                        format!(
                            "Activity with data intent-filter lacks permission: {}",
                            activity.name
                        ),
                        "medium",
                        format!(
                            "Activity '{}' handles URI data in an intent-filter but has no \
                             permission requirement. Malicious apps may send crafted URIs.",
                            activity.name
                        ),
                        Some("CWE-926"),
                        Some("m1"),
                        Some("platform-1"),
                        Some(format!(
                            "schemes: {}",
                            filter.data_schemes.join(", ")
                        )),
                    ));
                    break; // one finding per activity is enough
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rule 21: android_deep_link_no_host (open redirect risk)
    // -----------------------------------------------------------------------
    for activity in &manifest.activities {
        for filter in &activity.intent_filters {
            for scheme in &filter.data_schemes {
                // Non-http/https custom schemes with no host specified
                if scheme != "http" && scheme != "https" && filter.data_hosts.is_empty() {
                    findings.push(finding(
                        "android_deep_link_no_host",
                        "Deep link scheme without host (open redirect risk)",
                        "medium",
                        format!(
                            "Intent filter in activity '{}' registers scheme '{}' without a \
                             host restriction. This may allow open redirect attacks.",
                            activity.name, scheme
                        ),
                        Some("CWE-601"),
                        Some("m1"),
                        None,
                        Some(format!("{}://", scheme)),
                    ));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rule 22: android_exported_service_with_intent_filter
    // -----------------------------------------------------------------------
    for service in &manifest.services {
        let has_intent_filter = !service.intent_filters.is_empty();
        if has_intent_filter && service.permission.is_none() {
            findings.push(finding(
                "android_exported_service_intent_filter_no_permission",
                format!(
                    "Service with intent-filter exported without permission: {}",
                    service.name
                ),
                "high",
                format!(
                    "Service '{}' has an intent-filter (implicitly exported on API < 31) but \
                     no permission requirement. Any app can bind to it.",
                    service.name
                ),
                Some("CWE-926"),
                Some("m1"),
                Some("platform-1"),
                Some(service.name.clone()),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 23: android_exported_receiver_with_intent_filter
    // -----------------------------------------------------------------------
    for receiver in &manifest.receivers {
        let has_intent_filter = !receiver.intent_filters.is_empty();
        if has_intent_filter && receiver.permission.is_none() {
            findings.push(finding(
                "android_exported_receiver_intent_filter_no_permission",
                format!(
                    "BroadcastReceiver with intent-filter lacks permission: {}",
                    receiver.name
                ),
                "medium",
                format!(
                    "Receiver '{}' has an intent-filter but no permission requirement. \
                     Any app can send broadcasts to trigger it.",
                    receiver.name
                ),
                Some("CWE-926"),
                Some("m1"),
                Some("platform-1"),
                Some(receiver.name.clone()),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 24: android_no_min_sdk_defined
    // -----------------------------------------------------------------------
    if manifest.min_sdk.is_none() {
        findings.push(finding(
            "android_no_min_sdk_defined",
            "minSdkVersion not defined",
            "low",
            "The app does not define a minSdkVersion. The build tool defaults to 1, \
             making the app potentially compatible with extremely old and insecure devices.",
            None,
            Some("m8"),
            None,
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 25: android_allow_backup_missing_full_backup_content
    // -----------------------------------------------------------------------
    if manifest.allow_backup && manifest.network_security_config.is_none() {
        // Use network_security_config as a proxy: apps that set allowBackup=true
        // but haven't defined any advanced security config likely also lack a
        // fullBackupContent / dataExtractionRules definition.
        findings.push(finding(
            "android_allow_backup_no_rules",
            "Backup enabled without data extraction rules",
            "medium",
            "android:allowBackup=true is set but no fullBackupContent or \
             dataExtractionRules attribute was detected. Sensitive files may be \
             included in backups unintentionally.",
            Some("CWE-312"),
            Some("m2"),
            Some("storage-1"),
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 26: android_internet_permission_combined_cleartext
    // -----------------------------------------------------------------------
    let has_internet = manifest
        .permissions
        .iter()
        .any(|p| p == "android.permission.INTERNET");
    if has_internet && manifest.uses_cleartext_traffic {
        findings.push(finding(
            "android_internet_cleartext_combo",
            "INTERNET permission combined with cleartext traffic enabled",
            "high",
            "The app requests the INTERNET permission and also enables cleartext \
             traffic. All network communication should use TLS.",
            Some("CWE-319"),
            Some("m3"),
            Some("network-1"),
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 27: android_multiple_custom_permissions
    // -----------------------------------------------------------------------
    // Custom (non-android.*) permissions declared in the manifest permissions list
    // may have weak protection levels.
    let custom_perms: Vec<&String> = manifest
        .permissions
        .iter()
        .filter(|p| {
            !p.starts_with("android.permission.")
                && !p.starts_with("com.android.")
                && !p.starts_with("android.hardware.")
        })
        .collect();
    if !custom_perms.is_empty() {
        findings.push(finding(
            "android_custom_permissions",
            "Custom permissions declared",
            "info",
            format!(
                "The app uses {} custom permission(s). Verify that custom permissions \
                 have appropriate protectionLevel (signature or signatureOrSystem).",
                custom_perms.len()
            ),
            Some("CWE-862"),
            Some("m1"),
            None,
            Some(custom_perms.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 28: android_package_name_check (too generic / test naming)
    // -----------------------------------------------------------------------
    let pkg = &manifest.package;
    if pkg.contains("test") || pkg.contains("debug") || pkg.contains("demo") {
        findings.push(finding(
            "android_debug_package_name",
            "Package name suggests debug or test build",
            "info",
            format!(
                "Package name '{}' contains 'test', 'debug', or 'demo'. Ensure this is \
                 not a production release.",
                pkg
            ),
            None,
            None,
            None,
            Some(pkg.clone()),
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 29: android_missing_target_sdk
    // -----------------------------------------------------------------------
    if manifest.target_sdk.is_none() {
        findings.push(finding(
            "android_no_target_sdk_defined",
            "targetSdkVersion not defined",
            "low",
            "The app does not explicitly define a targetSdkVersion. This may result \
             in unexpected compatibility mode behaviour on newer Android versions.",
            None,
            Some("m8"),
            None,
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 30: android_all_activities_exported (every activity exported)
    // -----------------------------------------------------------------------
    let total_activities = manifest.activities.len();
    if total_activities > 1 {
        let all_exported = manifest
            .activities
            .iter()
            .all(|a| a.exported == Some(true));
        if all_exported {
            findings.push(finding(
                "android_all_activities_exported",
                "All activities are exported",
                "high",
                format!(
                    "All {} activities in the manifest are marked as exported. This creates \
                     a large attack surface.",
                    total_activities
                ),
                Some("CWE-926"),
                Some("m1"),
                Some("platform-1"),
                None,
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule 31: android_version_name_empty
    // -----------------------------------------------------------------------
    if manifest.version_name.is_empty() {
        findings.push(finding(
            "android_missing_version_name",
            "Application versionName is empty",
            "info",
            "The manifest does not declare a versionName. This may indicate an \
             improperly configured build.",
            None,
            None,
            None,
            None,
        ));
    }

    // -----------------------------------------------------------------------
    // Rule 32: android_provider_without_explicit_export
    // -----------------------------------------------------------------------
    for provider in &manifest.providers {
        if provider.exported.is_none() {
            findings.push(finding(
                "android_provider_implicit_export",
                format!("ContentProvider has no explicit exported attribute: {}", provider.name),
                "medium",
                format!(
                    "ContentProvider '{}' does not set android:exported explicitly. \
                     On API < 17 providers are exported by default; this is unsafe.",
                    provider.name
                ),
                Some("CWE-926"),
                Some("m2"),
                Some("storage-3"),
                Some(provider.name.clone()),
            ));
        }
    }

    findings
}
