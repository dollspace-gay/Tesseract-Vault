//! Password validation and input handling.
//!
//! This module provides functionality for validating password strength
//! and securely collecting passwords from users.
//!
//! # Password Strength Estimation
//!
//! On native platforms, uses [zxcvbn](https://github.com/dropbox/zxcvbn) for
//! entropy-based password strength estimation. This approach recognizes common patterns:
//!
//! - Dictionary words and common passwords
//! - Keyboard patterns (qwerty, 123456)
//! - Repeated characters and sequences
//! - L33t speak substitutions
//! - Date patterns
//!
//! This is more effective than complexity rules (requiring uppercase, numbers, etc.)
//! which users often satisfy with predictable patterns like "Password1!".
//!
//! On WASM, falls back to complexity-based validation since zxcvbn is not available.

use crate::error::{CryptorError, Result};
#[cfg(not(target_arch = "wasm32"))]
use rpassword::read_password;
#[cfg(not(target_arch = "wasm32"))]
use std::io::Write;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Minimum password length required.
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Minimum zxcvbn score required (0-4 scale).
/// Score::Three = "safely unguessable: moderate protection from offline slow-hash scenario"
#[cfg(not(target_arch = "wasm32"))]
pub const MIN_ENTROPY_SCORE: zxcvbn::Score = zxcvbn::Score::Three;

/// Minimum complexity score (number of character types required).
/// Used on WASM where zxcvbn is not available.
#[cfg(target_arch = "wasm32")]
pub const MIN_COMPLEXITY_SCORE: u8 = 3;

/// Prompts the user for a password and validates it.
///
/// This function:
/// - Prompts for a password (hidden input)
/// - Validates password strength using entropy estimation
/// - Prompts for confirmation
/// - Verifies both passwords match using constant-time comparison
///
/// # Errors
///
/// Returns an error if:
/// - Password fails validation
/// - Passwords don't match
/// - I/O error occurs during input
///
/// # Security
///
/// - Uses zeroizing memory to prevent password leakage
/// - Constant-time comparison to prevent timing attacks
#[cfg(not(target_arch = "wasm32"))]
pub fn get_and_validate_password() -> Result<Zeroizing<String>> {
    print!("Enter a strong password: ");
    std::io::stdout().flush()?;
    let pass1 = Zeroizing::new(read_password()?);

    validate_password(&pass1)?;

    print!("Confirm password: ");
    std::io::stdout().flush()?;
    let pass2 = Zeroizing::new(read_password()?);

    if !bool::from(pass1.as_bytes().ct_eq(pass2.as_bytes())) {
        return Err(CryptorError::PasswordValidation(
            "Passwords do not match.".to_string(),
        ));
    }

    Ok(pass1)
}

/// Prompts the user for a password without validation (for decryption).
///
/// # Errors
///
/// Returns an error if I/O error occurs during input.
#[cfg(not(target_arch = "wasm32"))]
pub fn get_password() -> Result<Zeroizing<String>> {
    print!("Enter password: ");
    std::io::stdout().flush()?;
    Ok(Zeroizing::new(read_password()?))
}

/// Validates password strength using entropy estimation (native) or complexity rules (WASM).
///
/// # Native Platforms
///
/// Uses zxcvbn for entropy-based validation. Password must:
/// - Be at least 12 characters long
/// - Achieve a zxcvbn score of 3 or higher (0-4 scale)
///
/// Score meanings:
/// - 0: Too guessable (risky password)
/// - 1: Very guessable (protection from throttled online attacks)
/// - 2: Somewhat guessable (protection from unthrottled online attacks)
/// - 3: Safely unguessable (moderate protection from offline slow-hash scenario)
/// - 4: Very unguessable (strong protection from offline slow-hash scenario)
///
/// # WASM
///
/// Falls back to complexity-based validation requiring:
/// - At least 12 characters
/// - At least 3 of: uppercase, lowercase, numbers, special characters
///
/// # Arguments
///
/// * `password` - The password to validate
///
/// # Errors
///
/// Returns an error with feedback if password doesn't meet requirements.
///
/// # Examples
///
/// ```
/// # use tesseract_lib::validation::validate_password;
/// // Strong random password - should pass
/// assert!(validate_password("K7#mPx9@nL2$qR").is_ok());
///
/// // Too short
/// assert!(validate_password("Short1!").is_err());
///
/// // Common password pattern - fails entropy check
/// assert!(validate_password("Password123!").is_err());
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn validate_password(password: &str) -> Result<()> {
    // Check minimum length first
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(CryptorError::PasswordValidation(format!(
            "Password must be at least {} characters long.",
            MIN_PASSWORD_LENGTH
        )));
    }

    // Use zxcvbn for entropy-based strength estimation
    let entropy = zxcvbn::zxcvbn(password, &[]);
    let score = entropy.score();

    if score < MIN_ENTROPY_SCORE {
        // Build helpful feedback message
        let mut feedback_parts = Vec::new();

        if let Some(feedback) = entropy.feedback() {
            if let Some(warning) = feedback.warning() {
                feedback_parts.push(format!("Warning: {}", warning));
            }
            for suggestion in feedback.suggestions() {
                feedback_parts.push(format!("Suggestion: {}", suggestion));
            }
        }

        let feedback_msg = if feedback_parts.is_empty() {
            "Password is too weak. Try using a longer passphrase with random words.".to_string()
        } else {
            feedback_parts.join(" ")
        };

        return Err(CryptorError::PasswordValidation(format!(
            "Password strength score {} is below required minimum of {} (scale 0-4). {}",
            u8::from(score), u8::from(MIN_ENTROPY_SCORE), feedback_msg
        )));
    }

    Ok(())
}

/// WASM fallback: complexity-based password validation.
///
/// Password must:
/// - Be at least 12 characters long
/// - Contain at least 3 of the following:
///   - Uppercase letters
///   - Lowercase letters
///   - Numbers
///   - Special characters
#[cfg(target_arch = "wasm32")]
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(CryptorError::PasswordValidation(format!(
            "Password must be at least {} characters long.",
            MIN_PASSWORD_LENGTH
        )));
    }

    let has_uppercase = password.chars().any(char::is_uppercase);
    let has_lowercase = password.chars().any(char::is_lowercase);
    let has_numeric = password.chars().any(char::is_numeric);
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let complexity_score =
        has_uppercase as u8 + has_lowercase as u8 + has_numeric as u8 + has_special as u8;

    if complexity_score < MIN_COMPLEXITY_SCORE {
        return Err(CryptorError::PasswordValidation(
            format!("Password must contain at least {} of the following categories: uppercase, lowercase, numbers, special characters.", MIN_COMPLEXITY_SCORE)
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_too_short() {
        assert!(validate_password("Short1!").is_err());
    }

    #[test]
    fn test_weak_common_passwords() {
        // These pass old complexity rules but fail entropy check
        assert!(validate_password("Password123!").is_err());
        assert!(validate_password("Qwerty12345!").is_err());
        assert!(validate_password("Welcome2024!").is_err());
    }

    #[test]
    fn test_simple_patterns_rejected() {
        // Repeated characters
        assert!(validate_password("aaaaaaaaaaaa").is_err());
        // Sequential patterns
        assert!(validate_password("abcdefghijkl").is_err());
        assert!(validate_password("123456789012").is_err());
    }

    #[test]
    fn test_strong_random_passwords() {
        // Truly random passwords should pass
        assert!(validate_password("K7#mPx9@nL2$qR").is_ok());
        assert!(validate_password("xQ8!vN3@pM5$bH").is_ok());
        assert!(validate_password("j2$Kf9#Lm4@Np7").is_ok());
    }

    #[test]
    fn test_passphrases() {
        // Long passphrases with some randomness should pass
        assert!(validate_password("correct-horse-battery-staple-7").is_ok());
        assert!(validate_password("purple-monkey-dishwasher-42!").is_ok());
    }

    #[test]
    fn test_password_exactly_min_length() {
        // 12 chars, random enough to pass
        assert!(validate_password("k7#mPx9@nL2$").is_ok());
    }

    #[test]
    fn test_password_unicode() {
        // Unicode characters add entropy
        assert!(validate_password("Abcdefgh123😀🎉").is_ok());
    }

    #[test]
    fn test_entropy_score_feedback() {
        // Verify weak passwords get rejected with helpful feedback
        let result = validate_password("Password123!");
        assert!(result.is_err());
        if let Err(CryptorError::PasswordValidation(msg)) = result {
            assert!(msg.contains("score"));
        }
    }
}
