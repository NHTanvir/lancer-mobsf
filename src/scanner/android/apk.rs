// APK extraction

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

/// Structured view of an extracted APK.
#[derive(Debug)]
pub struct ExtractedApk {
    /// The directory into which the APK was extracted.
    pub dir: PathBuf,
    /// Raw bytes of `AndroidManifest.xml` (binary AXML format).
    pub manifest_bytes: Vec<u8>,
    /// Paths to DEX files (`classes.dex`, `classes2.dex`, …).
    pub dex_files: Vec<PathBuf>,
    /// Paths to native shared libraries (`.so`) found under `lib/`.
    pub so_files: Vec<PathBuf>,
    /// Paths to signing-certificate files (`META-INF/*.RSA`, `*.DSA`, `*.EC`).
    pub cert_files: Vec<PathBuf>,
    /// Paths to resource files under `res/` and `assets/`.
    pub resource_files: Vec<PathBuf>,
}

/// Sanitise a zip entry name so it cannot escape `dest_dir`.
///
/// - Strips a leading `/` (absolute path).
/// - Removes every `..` component.
/// - Returns `None` if the result is empty (e.g. the entry *was* just `..`).
fn sanitise_zip_path(name: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in Path::new(name).components() {
        use std::path::Component;
        match component {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}           // skip `.`
            Component::ParentDir => {}        // drop `..`
            Component::RootDir => {}          // drop leading `/`
            Component::Prefix(_) => {}        // Windows drive prefix – ignore
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Extract an APK (zip) file into `dest_dir` and return categorised metadata.
///
/// The function is `async` because callers typically run in a Tokio context,
/// but the heavy lifting is synchronous I/O via the `zip` crate – that is
/// acceptable for the static-analysis use-case where the APK is already on
/// disk and is only extracted once.
pub async fn extract_apk(apk_path: &Path, dest_dir: &Path) -> Result<ExtractedApk> {
    // Ensure the destination directory exists.
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("create dest_dir {}", dest_dir.display()))?;

    let file = std::fs::File::open(apk_path)
        .with_context(|| format!("open APK {}", apk_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("read ZIP archive {}", apk_path.display()))?;

    let mut manifest_bytes: Vec<u8> = Vec::new();
    let mut dex_files: Vec<PathBuf> = Vec::new();
    let mut so_files: Vec<PathBuf> = Vec::new();
    let mut cert_files: Vec<PathBuf> = Vec::new();
    let mut resource_files: Vec<PathBuf> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)
            .with_context(|| format!("read ZIP entry {i}"))?;

        let entry_name = entry.name().to_owned();

        // Skip directory entries.
        if entry_name.ends_with('/') {
            continue;
        }

        let rel_path = match sanitise_zip_path(&entry_name) {
            Some(p) => p,
            None => continue,
        };

        let dest_path = dest_dir.join(&rel_path);

        // Create parent directories as needed.
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir {}", parent.display()))?;
        }

        // Write the entry to disk.
        let mut out_file = std::fs::File::create(&dest_path)
            .with_context(|| format!("create {}", dest_path.display()))?;
        std::io::copy(&mut entry, &mut out_file)
            .with_context(|| format!("extract {}", dest_path.display()))?;

        // Categorise by entry name / extension.
        let name_lower = entry_name.to_lowercase();

        if entry_name == "AndroidManifest.xml" {
            // Re-read the bytes for the manifest (already written to disk, but we
            // need them in memory for the parser).
            manifest_bytes = std::fs::read(&dest_path)
                .with_context(|| format!("read manifest from {}", dest_path.display()))?;
        } else if name_lower.ends_with(".dex") {
            dex_files.push(dest_path.clone());
        } else if name_lower.ends_with(".so") && name_lower.contains("lib/") {
            so_files.push(dest_path.clone());
        } else if name_lower.starts_with("meta-inf/")
            && (name_lower.ends_with(".rsa")
                || name_lower.ends_with(".dsa")
                || name_lower.ends_with(".ec"))
        {
            cert_files.push(dest_path.clone());
        } else if name_lower.starts_with("res/") || name_lower.starts_with("assets/") {
            resource_files.push(dest_path.clone());
        }
    }

    Ok(ExtractedApk {
        dir: dest_dir.to_path_buf(),
        manifest_bytes,
        dex_files,
        so_files,
        cert_files,
        resource_files,
    })
}
