// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
// Build script for platform-specific resource embedding

fn main() {
    // Embed Windows icon resource on Windows only
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icons/app_icon.ico");
        res.set("ProductName", "Secure Cryptor");
        res.set("FileDescription", "Secure File Encryption Tool");
        res.set("CompanyName", "Secure Cryptor");
        if let Err(e) = res.compile() {
            eprintln!("Failed to compile Windows resources: {}", e);
        }
    }

    // On other platforms, no special build steps required
    #[cfg(not(target_os = "windows"))]
    {
        println!("cargo:warning=Building for non-Windows platform (no icon embedding)");
    }
}
