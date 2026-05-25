// ELF hardening checks

use crate::scanner::ScanFinding;
use std::path::PathBuf;
use goblin::Object;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ElfHardening {
    pub path: String,
    pub arch: String,
    pub pie: bool,
    pub nx: bool,
    pub stack_canary: bool,
    pub relro: RelroType,
    pub rpath: bool,
    pub fortify: bool,
    pub stripped: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum RelroType {
    Full,
    Partial,
    None,
}

const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;
const PF_X: u32 = 1;
const DT_BIND_NOW: u64 = 24;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

/// Detect CPU arch from ELF machine type.
fn arch_from_machine(machine: u16) -> String {
    match machine {
        0x28 => "armeabi-v7a".to_string(),   // EM_ARM
        0xB7 => "arm64-v8a".to_string(),     // EM_AARCH64
        0x03 => "x86".to_string(),           // EM_386
        0x3E => "x86_64".to_string(),        // EM_X86_64
        0xF3 => "riscv".to_string(),         // EM_RISCV
        _ => format!("unknown(0x{:x})", machine),
    }
}

/// Analyze a single .so ELF file and return its hardening profile.
fn analyze_elf(path: &std::path::Path, bytes: &[u8]) -> Option<ElfHardening> {
    let object = match Object::parse(bytes) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "Failed to parse binary");
            return None;
        }
    };

    let elf = match object {
        Object::Elf(e) => e,
        _ => {
            tracing::warn!(path = %path.display(), "Not an ELF file, skipping");
            return None;
        }
    };

    let arch = arch_from_machine(elf.header.e_machine);

    // PIE: ET_DYN (3) = shared lib / PIE. For .so files this is always true.
    let pie = elf.header.e_type == 3; // ET_DYN

    // NX: Look for PT_GNU_STACK
    let mut nx = false;
    let mut has_gnu_relro = false;
    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            // NX enabled if NOT executable: flags == PF_R|PF_W (6), not PF_R|PF_W|PF_X (7)
            let flags = ph.p_flags;
            nx = (flags & PF_X) == 0;
        }
        if ph.p_type == PT_GNU_RELRO {
            has_gnu_relro = true;
        }
    }

    // Stack canary: check syms and dynsyms for __stack_chk_fail or __stack_chk_guard
    let canary_names = ["__stack_chk_fail", "__stack_chk_guard"];
    let mut stack_canary = false;

    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if canary_names.contains(&name) {
                stack_canary = true;
                break;
            }
        }
    }

    if !stack_canary {
        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if canary_names.contains(&name) {
                    stack_canary = true;
                    break;
                }
            }
        }
    }

    // RELRO: Full = has_gnu_relro + DT_BIND_NOW; Partial = has_gnu_relro only; None = neither
    let mut has_bind_now = false;
    let mut has_rpath = false;
    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            let tag = dyn_entry.d_tag as u64;
            if tag == DT_BIND_NOW {
                has_bind_now = true;
            }
            if tag == DT_RPATH || tag == DT_RUNPATH {
                // Check if value is non-empty (non-zero strtab offset)
                if dyn_entry.d_val != 0 {
                    has_rpath = true;
                }
            }
        }
    }

    let relro = if has_gnu_relro && has_bind_now {
        RelroType::Full
    } else if has_gnu_relro {
        RelroType::Partial
    } else {
        RelroType::None
    };

    // Fortify: dynsyms containing "_chk" suffix pattern
    let mut fortify = false;
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.contains("_chk") {
                fortify = true;
                break;
            }
        }
    }

    // Stripped: no symbol table (elf.syms is empty)
    let stripped = elf.syms.is_empty();

    Some(ElfHardening {
        path: path.to_string_lossy().to_string(),
        arch,
        pie,
        nx,
        stack_canary,
        relro,
        rpath: has_rpath,
        fortify,
        stripped,
    })
}

/// Analyze all .so files, return hardening info and findings.
pub fn analyze_binaries(so_files: &[PathBuf]) -> (Vec<ElfHardening>, Vec<ScanFinding>) {
    let mut hardenings = Vec::new();
    let mut findings = Vec::new();

    for path in so_files {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to read .so file");
                continue;
            }
        };

        let info = match analyze_elf(path, &bytes) {
            Some(h) => h,
            None => continue,
        };

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Generate findings for missing hardening features
        if !info.nx {
            findings.push(ScanFinding {
                rule_id: "elf_no_nx".to_string(),
                title: format!("No NX (Non-Executable Stack) in {filename}"),
                severity: "high".to_string(),
                description: format!(
                    "The native library '{filename}' does not have a non-executable stack (NX). \
                     This allows shellcode injection on the stack."
                ),
                file_path: Some(info.path.clone()),
                line_number: None,
                cwe: Some("CWE-119".to_string()),
                owasp: None,
                masvs: None,
                evidence: None,
            });
        }

        if !info.stack_canary {
            findings.push(ScanFinding {
                rule_id: "elf_no_stack_canary".to_string(),
                title: format!("No Stack Canary in {filename}"),
                severity: "high".to_string(),
                description: format!(
                    "The native library '{filename}' was not compiled with stack canary protection \
                     (__stack_chk_fail). This makes stack-based buffer overflows easier to exploit."
                ),
                file_path: Some(info.path.clone()),
                line_number: None,
                cwe: Some("CWE-121".to_string()),
                owasp: None,
                masvs: None,
                evidence: None,
            });
        }

        match &info.relro {
            RelroType::None => {
                findings.push(ScanFinding {
                    rule_id: "elf_no_relro".to_string(),
                    title: format!("No RELRO in {filename}"),
                    severity: "medium".to_string(),
                    description: format!(
                        "The native library '{filename}' has no RELRO protection. \
                         The GOT and other writable ELF sections may be exploitable."
                    ),
                    file_path: Some(info.path.clone()),
                    line_number: None,
                    cwe: Some("CWE-119".to_string()),
                    owasp: None,
                    masvs: None,
                    evidence: None,
                });
            }
            RelroType::Partial => {
                findings.push(ScanFinding {
                    rule_id: "elf_partial_relro".to_string(),
                    title: format!("Partial RELRO in {filename}"),
                    severity: "low".to_string(),
                    description: format!(
                        "The native library '{filename}' has only partial RELRO. \
                         Full RELRO (with BIND_NOW) is recommended."
                    ),
                    file_path: Some(info.path.clone()),
                    line_number: None,
                    cwe: Some("CWE-119".to_string()),
                    owasp: None,
                    masvs: None,
                    evidence: None,
                });
            }
            RelroType::Full => {}
        }

        if info.rpath {
            findings.push(ScanFinding {
                rule_id: "elf_rpath".to_string(),
                title: format!("Dangerous RPATH/RUNPATH in {filename}"),
                severity: "high".to_string(),
                description: format!(
                    "The native library '{filename}' contains RPATH/RUNPATH dynamic entries. \
                     This can be exploited for library hijacking attacks."
                ),
                file_path: Some(info.path.clone()),
                line_number: None,
                cwe: Some("CWE-427".to_string()),
                owasp: None,
                masvs: None,
                evidence: None,
            });
        }

        if !info.fortify {
            findings.push(ScanFinding {
                rule_id: "elf_no_fortify".to_string(),
                title: format!("No FORTIFY_SOURCE in {filename}"),
                severity: "low".to_string(),
                description: format!(
                    "The native library '{filename}' was not compiled with FORTIFY_SOURCE. \
                     Fortified variants of libc functions (e.g. __strcpy_chk) add runtime checks."
                ),
                file_path: Some(info.path.clone()),
                line_number: None,
                cwe: None,
                owasp: None,
                masvs: None,
                evidence: None,
            });
        }

        hardenings.push(info);
    }

    (hardenings, findings)
}
