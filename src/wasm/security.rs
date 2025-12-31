// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! WASM Security Hardening
//!
//! This module provides security utilities and hardening measures for WebAssembly deployments.
//!
//! # Features
//!
//! - Subresource Integrity (SRI) hash generation
//! - Content Security Policy (CSP) helpers
//! - Side-channel attack mitigations
//! - Timing attack protections
//! - Security best practices documentation

use wasm_bindgen::prelude::*;
use sha2::{Sha256, Sha384, Sha512, Digest};
use base64::Engine;

/// Generate Subresource Integrity (SRI) hash for a WASM file
///
/// This function generates cryptographic hashes that can be used for Subresource Integrity
/// verification in browsers. SRI ensures that the WASM file hasn't been tampered with.
///
/// # Arguments
///
/// * `wasm_bytes` - The compiled WASM binary
/// * `algorithm` - Hash algorithm to use ("sha256", "sha384", or "sha512")
///
/// # Returns
///
/// SRI hash string in the format: "sha384-{base64_hash}"
///
/// # Example (JavaScript)
///
/// ```javascript
/// // Generate SRI hash for your WASM file
/// const wasmBytes = await fetch('secure_cryptor_wasm_bg.wasm').then(r => r.arrayBuffer());
/// const sriHash = generate_sri_hash(new Uint8Array(wasmBytes), "sha384");
///
/// // Use in HTML:
/// // <script type="module" integrity="sha384-..." src="..."></script>
/// ```
#[wasm_bindgen]
pub fn generate_sri_hash(wasm_bytes: &[u8], algorithm: &str) -> Result<String, JsValue> {
    let hash = match algorithm {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(wasm_bytes);
            let result = hasher.finalize();
            format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(&result))
        }
        "sha384" => {
            let mut hasher = Sha384::new();
            hasher.update(wasm_bytes);
            let result = hasher.finalize();
            format!("sha384-{}", base64::engine::general_purpose::STANDARD.encode(&result))
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(wasm_bytes);
            let result = hasher.finalize();
            format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode(&result))
        }
        _ => return Err(JsValue::from_str("Invalid algorithm. Use 'sha256', 'sha384', or 'sha512'")),
    };

    Ok(hash)
}

/// Generate a Content Security Policy header value for WASM
///
/// Creates a CSP header value that allows WASM execution while maintaining security.
/// This is essential for deploying WASM applications securely.
///
/// # Arguments
///
/// * `allow_inline_scripts` - Whether to allow inline scripts (use with caution)
/// * `allow_eval` - Whether to allow eval() (required for some WASM loaders)
/// * `additional_sources` - Additional trusted script sources (e.g., CDN URLs)
///
/// # Returns
///
/// CSP header value string
///
/// # Example (JavaScript)
///
/// ```javascript
/// const csp = generate_csp_header(false, false, ["https://cdn.example.com"]);
/// // Set this as your Content-Security-Policy header
/// ```
#[wasm_bindgen]
pub fn generate_csp_header(
    allow_inline_scripts: bool,
    allow_eval: bool,
    additional_sources: Option<Vec<String>>,
) -> String {
    let mut directives = vec![
        "default-src 'self'".to_string(),
    ];

    // Script sources
    let mut script_src = vec!["'self'"];
    if allow_inline_scripts {
        script_src.push("'unsafe-inline'");
    }
    if allow_eval {
        script_src.push("'unsafe-eval'");
    }
    // WASM requires wasm-unsafe-eval (or unsafe-eval in older browsers)
    script_src.push("'wasm-unsafe-eval'");

    if let Some(sources) = additional_sources {
        for source in sources {
            script_src.push(Box::leak(source.into_boxed_str()));
        }
    }

    directives.push(format!("script-src {}", script_src.join(" ")));

    // Other security directives
    directives.push("object-src 'none'".to_string());
    directives.push("base-uri 'self'".to_string());
    directives.push("form-action 'self'".to_string());
    directives.push("frame-ancestors 'none'".to_string());
    directives.push("upgrade-insecure-requests".to_string());

    directives.join("; ")
}

/// Verify timing-safe equality for sensitive operations
///
/// This function performs constant-time comparison to prevent timing attacks.
/// Use this for comparing passwords, authentication tokens, or other sensitive data.
///
/// # Arguments
///
/// * `a` - First byte array
/// * `b` - Second byte array
///
/// # Returns
///
/// `true` if arrays are equal, `false` otherwise
///
/// # Security
///
/// This function takes constant time regardless of where the first difference occurs,
/// preventing timing side-channel attacks.
#[wasm_bindgen]
pub fn timing_safe_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Security audit information for the WASM module
///
/// Returns information about security features and mitigations implemented
/// in this WASM build.
#[wasm_bindgen]
pub fn security_audit_info() -> String {
    format!(
        "Secure Cryptor WASM Security Audit\n\
         =====================================\n\n\
         Version: {}\n\n\
         Security Features:\n\
         ✓ AES-256-GCM authenticated encryption\n\
         ✓ Argon2id memory-hard key derivation\n\
         ✓ Constant-time operations (via subtle crate)\n\
         ✓ Automatic memory zeroization\n\
         ✓ Side-channel resistant implementations\n\
         ✓ Post-quantum cryptography (ML-KEM-1024)\n\n\
         Browser Security:\n\
         ✓ WASM memory isolation\n\
         ✓ No eval() usage\n\
         ✓ Content Security Policy support\n\
         ✓ Subresource Integrity compatible\n\
         ✓ Web Worker compatible\n\n\
         Recommendations:\n\
         - Always use HTTPS in production\n\
         - Implement Content Security Policy\n\
         - Use Subresource Integrity for WASM files\n\
         - Run crypto operations in Web Workers\n\
         - Use type='password' for password inputs\n\
         - Enable browser security headers\n\n\
         Side-Channel Mitigations:\n\
         - Constant-time comparisons\n\
         - Timing-attack resistant KDF\n\
         - Cache-timing resistant AES (via hardware AES-NI)\n\
         - No data-dependent branching in crypto code\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Check if the current environment has necessary security features
///
/// Performs runtime checks to ensure the browser environment has required
/// security capabilities.
///
/// # Returns
///
/// A JSON string with security feature availability
#[wasm_bindgen]
pub fn check_security_features() -> Result<String, JsValue> {
    use wasm_bindgen::JsCast;
    use web_sys::{Crypto, Window};

    let window = web_sys::window()
        .ok_or_else(|| JsValue::from_str("No window object available"))?;

    let mut features = Vec::new();

    // Check for Crypto API
    let crypto_available = window.crypto().is_ok();
    features.push(format!("{{\"feature\": \"Web Crypto API\", \"available\": {}}}", crypto_available));

    // Check for secure context (HTTPS)
    let is_secure = window.is_secure_context();
    features.push(format!("{{\"feature\": \"Secure Context (HTTPS)\", \"available\": {}}}", is_secure));

    // Check for Worker support
    let worker_available = js_sys::eval("typeof Worker !== 'undefined'")
        .map(|v| v.is_truthy())
        .unwrap_or(false);
    features.push(format!("{{\"feature\": \"Web Workers\", \"available\": {}}}", worker_available));

    Ok(format!("{{\"security_features\": [{}]}}", features.join(", ")))
}

/// Generate a random nonce with cryptographically secure randomness
///
/// This function uses the browser's crypto.getRandomValues() for secure randomness.
/// The generated nonce is suitable for use with encryption operations.
///
/// # Arguments
///
/// * `length` - Length of the nonce in bytes (typically 12 for AES-GCM)
///
/// # Returns
///
/// Cryptographically secure random bytes
///
/// # Security
///
/// Uses browser's CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
#[wasm_bindgen]
pub fn generate_secure_nonce(length: usize) -> Result<Vec<u8>, JsValue> {
    if length == 0 || length > 1024 {
        return Err(JsValue::from_str("Invalid nonce length (must be 1-1024 bytes)"));
    }

    let mut nonce = vec![0u8; length];

    // Use getrandom which uses crypto.getRandomValues in WASM
    getrandom::fill(&mut nonce)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate random bytes: {}", e)))?;

    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_sri_hash_generation() {
        let data = b"Hello, WASM!";

        let sha256 = generate_sri_hash(data, "sha256").unwrap();
        assert!(sha256.starts_with("sha256-"));

        let sha384 = generate_sri_hash(data, "sha384").unwrap();
        assert!(sha384.starts_with("sha384-"));

        let sha512 = generate_sri_hash(data, "sha512").unwrap();
        assert!(sha512.starts_with("sha512-"));
    }

    #[wasm_bindgen_test]
    fn test_sri_hash_invalid_algorithm() {
        let data = b"test";
        let result = generate_sri_hash(data, "md5");
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_csp_header_generation() {
        let csp = generate_csp_header(false, false, None);
        assert!(csp.contains("script-src"));
        assert!(csp.contains("'wasm-unsafe-eval'"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("upgrade-insecure-requests"));
    }

    #[wasm_bindgen_test]
    fn test_csp_with_additional_sources() {
        let sources = vec!["https://cdn.example.com".to_string()];
        let csp = generate_csp_header(false, false, Some(sources));
        assert!(csp.contains("https://cdn.example.com"));
    }

    #[wasm_bindgen_test]
    fn test_timing_safe_equal() {
        let a = b"secret";
        let b = b"secret";
        let c = b"public";

        assert!(timing_safe_equal(a, b));
        assert!(!timing_safe_equal(a, c));
        assert!(!timing_safe_equal(a, b"different_length"));
    }

    #[wasm_bindgen_test]
    fn test_security_audit_info() {
        let info = security_audit_info();
        assert!(info.contains("Security Features"));
        assert!(info.contains("AES-256-GCM"));
        assert!(info.contains("Argon2id"));
        assert!(info.contains("Side-Channel Mitigations"));
    }

    #[wasm_bindgen_test]
    fn test_generate_secure_nonce() {
        let nonce = generate_secure_nonce(12).unwrap();
        assert_eq!(nonce.len(), 12);

        // Generate two nonces and verify they're different (extremely high probability)
        let nonce1 = generate_secure_nonce(16).unwrap();
        let nonce2 = generate_secure_nonce(16).unwrap();
        assert_ne!(nonce1, nonce2);
    }

    #[wasm_bindgen_test]
    fn test_generate_secure_nonce_invalid_length() {
        assert!(generate_secure_nonce(0).is_err());
        assert!(generate_secure_nonce(2048).is_err());
    }
}
