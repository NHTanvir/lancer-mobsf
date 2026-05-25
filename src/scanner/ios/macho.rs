// Mach-O binary hardening analysis

use crate::scanner::ScanFinding;
use std::path::Path;
use goblin::Object;
use goblin::mach::Mach;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::constants::cputype::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64,
};
use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MachoHardening {
    pub path: String,
    pub arch: String,
    pub is_pie: bool,
    pub has_arc: bool,
    pub has_stack_canary: bool,
    pub is_encrypted: bool,
    pub has_code_signature: bool,
    pub is_stripped: bool,
    pub rpath_count: usize,
    pub weak_frameworks: Vec<String>,
}

const MH_PIE: u32 = 0x0020_0000;

fn arch_from_cputype(cputype: u32) -> String {
    match cputype {
        t if t == CPU_TYPE_ARM64 as u32 => "arm64".to_string(),
        t if t == CPU_TYPE_ARM as u32 => "armv7".to_string(),
        t if t == CPU_TYPE_X86_64 as u32 => "x86_64".to_string(),
        t if t == CPU_TYPE_X86 as u32 => "x86".to_string(),
        other => format!("unknown(0x{:x})", other),
    }
}

pub fn analyze_macho(binary_path: &Path) -> Result<(MachoHardening, Vec<ScanFinding>)> {
    let bytes = std::fs::read(binary_path)?;
    let path_str = binary_path.to_string_lossy().to_string();

    let object = Object::parse(&bytes)?;

    let macho = match object {
        Object::Mach(mach) => match mach {
            Mach::Binary(m) => m,
            Mach::Fat(multi) => {
                // Use the first architecture slice
                let first_slice = multi.into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Fat binary has no architectures"))??;
                match first_slice {
                    goblin::mach::SingleArch::MachO(m) => m,
                    goblin::mach::SingleArch::Archive(_) => {
                        return Err(anyhow::anyhow!("First fat arch slice is an archive, not Mach-O"));
                    }
                }
            }
        },
        _ => return Err(anyhow::anyhow!("Not a Mach-O binary")),
    };

    let arch = arch_from_cputype(macho.header.cputype);

    // PIE check: MH_PIE flag in header.flags
    let is_pie = (macho.header.flags & MH_PIE) != 0;

    // ARC check: look for _objc_release symbol
    let mut has_arc = false;
    let mut has_stack_canary = false;
    let mut is_stripped = true;

    if let Some(ref syms) = macho.symbols {
        for sym_result in syms.iter() {
            if let Ok((name, _nlist)) = sym_result {
                is_stripped = false;
                if name.contains("_objc_release") {
                    has_arc = true;
                }
                if name.contains("___stack_chk_fail") || name.contains("__stack_chk_fail") {
                    has_stack_canary = true;
                }
            }
        }
        // If we iterated but found nothing, still false - but check the symbols count
        // is_stripped means no symbols at all
    } else {
        // No symbol table = stripped
        is_stripped = true;
    }

    // Check for symbols in dynsym-equivalent via libs imports if needed
    // Also check libs for common frameworks that imply ARC
    // (ARC was made mandatory in iOS 11 for new submissions, so this is mostly informational)

    // Parse load commands
    let mut is_encrypted = false;
    let mut has_code_signature = false;
    let mut rpath_count = 0usize;

    // Build weak_frameworks list by correlating load_commands order with libs
    // libs[0] = "self", then each LoadDylib/LoadWeakDylib/etc. in order
    let mut lib_index = 1usize; // start after "self"
    let mut weak_frameworks: Vec<String> = Vec::new();

    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::EncryptionInfo32(enc) => {
                if enc.cryptid != 0 {
                    is_encrypted = true;
                }
            }
            CommandVariant::EncryptionInfo64(enc) => {
                if enc.cryptid != 0 {
                    is_encrypted = true;
                }
            }
            CommandVariant::CodeSignature(_) => {
                has_code_signature = true;
            }
            CommandVariant::Rpath(_) => {
                rpath_count += 1;
            }
            CommandVariant::LoadWeakDylib(_) => {
                // Get the corresponding name from libs vec
                if let Some(name) = macho.libs.get(lib_index) {
                    weak_frameworks.push(name.to_string());
                }
                lib_index += 1;
            }
            CommandVariant::LoadDylib(_)
            | CommandVariant::LoadUpwardDylib(_)
            | CommandVariant::ReexportDylib(_)
            | CommandVariant::LazyLoadDylib(_) => {
                lib_index += 1;
            }
            _ => {}
        }
    }

    let hardening = MachoHardening {
        path: path_str.clone(),
        arch,
        is_pie,
        has_arc,
        has_stack_canary,
        is_encrypted,
        has_code_signature,
        is_stripped,
        rpath_count,
        weak_frameworks,
    };

    // Generate findings
    let mut findings = Vec::new();

    if !hardening.is_pie {
        findings.push(ScanFinding {
            rule_id: "ios_no_pie".to_string(),
            title: "Binary lacks PIE (Position Independent Executable)".to_string(),
            severity: "high".to_string(),
            description: "The binary does not have the MH_PIE flag set. Without PIE, \
                ASLR cannot randomize the base address of the main binary, making \
                exploitation of memory corruption bugs easier."
                .to_string(),
            file_path: Some(path_str.clone()),
            line_number: None,
            cwe: Some("CWE-119".to_string()),
            owasp: None,
            masvs: Some("MASVS-RESILIENCE-2".to_string()),
            evidence: Some(format!("header.flags = 0x{:08x}", macho.header.flags)),
        });
    }

    if !hardening.has_arc {
        findings.push(ScanFinding {
            rule_id: "ios_no_arc".to_string(),
            title: "Binary lacks ARC (Automatic Reference Counting)".to_string(),
            severity: "medium".to_string(),
            description: "The _objc_release symbol was not found in the binary, suggesting \
                it was not compiled with Automatic Reference Counting (ARC). Without ARC, \
                manual memory management increases the risk of use-after-free and \
                double-free vulnerabilities."
                .to_string(),
            file_path: Some(path_str.clone()),
            line_number: None,
            cwe: Some("CWE-119".to_string()),
            owasp: None,
            masvs: Some("MASVS-RESILIENCE-2".to_string()),
            evidence: None,
        });
    }

    if !hardening.has_stack_canary {
        findings.push(ScanFinding {
            rule_id: "ios_no_stack_canary".to_string(),
            title: "Binary lacks stack canary protection".to_string(),
            severity: "high".to_string(),
            description: "The ___stack_chk_fail symbol was not found, indicating the binary \
                was not compiled with stack canary protection. Stack canaries detect \
                stack-based buffer overflows before the function return address is \
                overwritten."
                .to_string(),
            file_path: Some(path_str.clone()),
            line_number: None,
            cwe: Some("CWE-121".to_string()),
            owasp: None,
            masvs: Some("MASVS-RESILIENCE-2".to_string()),
            evidence: None,
        });
    }

    if !hardening.is_encrypted {
        findings.push(ScanFinding {
            rule_id: "ios_not_encrypted".to_string(),
            title: "Binary is not encrypted (not App Store distributed)".to_string(),
            severity: "info".to_string(),
            description: "The binary has no LC_ENCRYPTION_INFO/LC_ENCRYPTION_INFO_64 load \
                command with a non-zero cryptid. This may indicate the binary was not \
                distributed through the App Store, or the encryption has been stripped."
                .to_string(),
            file_path: Some(path_str.clone()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: None,
        });
    }

    if !hardening.has_code_signature {
        findings.push(ScanFinding {
            rule_id: "ios_no_code_signature".to_string(),
            title: "Binary has no code signature".to_string(),
            severity: "high".to_string(),
            description: "The binary is missing an LC_CODE_SIGNATURE load command. \
                Without a code signature, iOS cannot verify the integrity or origin \
                of the binary. The app would be rejected by iOS at launch."
                .to_string(),
            file_path: Some(path_str.clone()),
            line_number: None,
            cwe: Some("CWE-347".to_string()),
            owasp: None,
            masvs: Some("MASVS-INTEGRITY-1".to_string()),
            evidence: None,
        });
    }

    if hardening.rpath_count > 0 {
        findings.push(ScanFinding {
            rule_id: "ios_rpath_present".to_string(),
            title: format!("Binary has {} RPATH (LC_RPATH) entries", hardening.rpath_count),
            severity: "medium".to_string(),
            description: "The binary contains LC_RPATH load commands. RPATH entries can \
                be abused for library injection/hijacking if an attacker can place a \
                malicious dylib in an RPATH-listed directory."
                .to_string(),
            file_path: Some(path_str.clone()),
            line_number: None,
            cwe: Some("CWE-427".to_string()),
            owasp: None,
            masvs: None,
            evidence: Some(format!("LC_RPATH count: {}", hardening.rpath_count)),
        });
    }

    Ok((hardening, findings))
}
