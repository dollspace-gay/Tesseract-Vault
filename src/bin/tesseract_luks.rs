// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! tesseract-luks CLI - Secure LUKS keyfile management
//!
//! Provides Tesseract security features for LUKS full disk encryption:
//! - ML-KEM-1024 post-quantum hybrid encryption
//! - TPM 2.0 auto-unlock with PCR binding
//! - Duress password support
//! - Argon2id key derivation
//!
//! # Usage
//!
//! ```bash
//! # Create a new keyfile
//! tesseract-luks create /etc/tesseract/root.keyfile
//!
//! # Unlock and pipe to cryptsetup
//! tesseract-luks unlock /etc/tesseract/root.keyfile | cryptsetup open /dev/sda2 root --key-file -
//!
//! # Enroll TPM for auto-unlock
//! tesseract-luks enroll-tpm /etc/tesseract/root.keyfile --pcrs 0,7
//!
//! # Set duress password
//! tesseract-luks set-duress /etc/tesseract/root.keyfile
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::io::{self, Write};

#[cfg(target_os = "linux")]
use tesseract_lib::luks::{LuksConfig, TesseractLuksKeyfile};

/// Tesseract LUKS - Secure keyfile management for LUKS full disk encryption
#[derive(Parser)]
#[command(name = "tesseract-luks")]
#[command(author = "Tesseract Project")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Secure LUKS keyfile management with PQC, TPM, and duress password support")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new Tesseract LUKS keyfile
    Create {
        /// Path to create the keyfile
        keyfile: PathBuf,

        /// Enable post-quantum hybrid encryption (ML-KEM-1024)
        #[arg(long, default_value = "true")]
        pqc: bool,

        /// Disable post-quantum encryption
        #[arg(long, conflicts_with = "pqc")]
        no_pqc: bool,
    },

    /// Unlock a keyfile and output the LUKS passphrase
    ///
    /// Outputs raw passphrase to stdout for piping to cryptsetup:
    /// tesseract-luks unlock keyfile | cryptsetup open /dev/sda2 root --key-file -
    Unlock {
        /// Path to the keyfile
        keyfile: PathBuf,
    },

    /// Unlock using TPM auto-unlock (no password required)
    UnlockTpm {
        /// Path to the keyfile
        keyfile: PathBuf,
    },

    /// Enroll TPM for auto-unlock
    EnrollTpm {
        /// Path to the keyfile
        keyfile: PathBuf,

        /// PCR indices to bind to (comma-separated, e.g., "0,7")
        #[arg(long, default_value = "0,7")]
        pcrs: String,
    },

    /// Set a duress password that destroys all keys when used
    SetDuress {
        /// Path to the keyfile
        keyfile: PathBuf,
    },

    /// Remove the duress password
    RemoveDuress {
        /// Path to the keyfile
        keyfile: PathBuf,
    },

    /// Show keyfile information
    Info {
        /// Path to the keyfile
        keyfile: PathBuf,
    },

    /// Change the Tesseract password
    ChangePassword {
        /// Path to the keyfile
        keyfile: PathBuf,
    },
}

fn main() -> ExitCode {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Error: tesseract-luks is only available on Linux");
        ExitCode::FAILURE
    }

    #[cfg(target_os = "linux")]
    {
        let cli = Cli::parse();

        match run_command(cli.command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {}", e);
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn run_command(cmd: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Commands::Create {
            keyfile,
            pqc,
            no_pqc,
        } => cmd_create(keyfile, pqc && !no_pqc),
        Commands::Unlock { keyfile } => cmd_unlock(keyfile),
        Commands::UnlockTpm { keyfile } => cmd_unlock_tpm(keyfile),
        Commands::EnrollTpm { keyfile, pcrs } => cmd_enroll_tpm(keyfile, &pcrs),
        Commands::SetDuress { keyfile } => cmd_set_duress(keyfile),
        Commands::RemoveDuress { keyfile } => cmd_remove_duress(keyfile),
        Commands::Info { keyfile } => cmd_info(keyfile),
        Commands::ChangePassword { keyfile } => cmd_change_password(keyfile),
    }
}

#[cfg(target_os = "linux")]
fn cmd_create(keyfile: PathBuf, enable_pqc: bool) -> Result<(), Box<dyn std::error::Error>> {
    use rpassword::prompt_password;

    if keyfile.exists() {
        return Err(format!("Keyfile already exists: {}", keyfile.display()).into());
    }

    eprintln!("Creating new Tesseract LUKS keyfile: {}", keyfile.display());
    eprintln!();

    // Get LUKS passphrase
    eprintln!("Enter the LUKS passphrase (the one you use with cryptsetup):");
    let luks_pass = prompt_password("LUKS passphrase: ")?;
    let luks_pass_confirm = prompt_password("Confirm LUKS passphrase: ")?;

    if luks_pass != luks_pass_confirm {
        return Err("LUKS passphrases do not match".into());
    }

    if luks_pass.is_empty() {
        return Err("LUKS passphrase cannot be empty".into());
    }

    eprintln!();

    // Get Tesseract password
    eprintln!("Enter a Tesseract password to protect this keyfile:");
    let tess_pass = prompt_password("Tesseract password: ")?;
    let tess_pass_confirm = prompt_password("Confirm Tesseract password: ")?;

    if tess_pass != tess_pass_confirm {
        return Err("Tesseract passwords do not match".into());
    }

    if tess_pass.len() < 8 {
        return Err("Tesseract password must be at least 8 characters".into());
    }

    // Create keyfile
    let config = LuksConfig {
        enable_pqc,
        enable_tpm: false,
        enable_yubikey: false,
        ..Default::default()
    };

    let keyfile_obj = TesseractLuksKeyfile::new(&luks_pass, &tess_pass, config)?;
    keyfile_obj.save(&keyfile)?;

    eprintln!();
    eprintln!("✓ Keyfile created successfully");
    if enable_pqc {
        eprintln!("✓ Post-quantum hybrid encryption enabled (ML-KEM-1024)");
    }
    eprintln!();
    eprintln!("Next steps:");
    eprintln!(
        "  1. Test unlocking: tesseract-luks unlock {}",
        keyfile.display()
    );
    eprintln!(
        "  2. Enroll TPM: tesseract-luks enroll-tpm {} --pcrs 0,7",
        keyfile.display()
    );
    eprintln!(
        "  3. Set duress: tesseract-luks set-duress {}",
        keyfile.display()
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_unlock(keyfile: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use rpassword::prompt_password;

    if !keyfile.exists() {
        return Err(format!("Keyfile not found: {}", keyfile.display()).into());
    }

    // Read password from stderr so stdout is clean for piping
    let password = prompt_password("Tesseract password: ")?;

    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;

    match keyfile_obj.unlock(&password) {
        Ok(passphrase) => {
            // Output raw passphrase to stdout (no newline for cryptsetup compatibility)
            io::stdout().write_all(passphrase.as_bytes())?;
            io::stdout().flush()?;
            Ok(())
        }
        Err(e) => Err(format!("Failed to unlock: {}", e).into()),
    }
}

#[cfg(target_os = "linux")]
fn cmd_unlock_tpm(keyfile: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !keyfile.exists() {
        return Err(format!("Keyfile not found: {}", keyfile.display()).into());
    }

    let keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;

    if !keyfile_obj.has_tpm() {
        return Err("TPM is not enrolled for this keyfile. Use 'enroll-tpm' first.".into());
    }

    match keyfile_obj.unlock_with_tpm() {
        Ok(passphrase) => {
            // Output raw passphrase to stdout
            io::stdout().write_all(passphrase.as_bytes())?;
            io::stdout().flush()?;
            Ok(())
        }
        Err(e) => Err(format!("TPM unlock failed: {}", e).into()),
    }
}

#[cfg(target_os = "linux")]
fn cmd_enroll_tpm(keyfile: PathBuf, pcrs: &str) -> Result<(), Box<dyn std::error::Error>> {
    use rpassword::prompt_password;

    if !keyfile.exists() {
        return Err(format!("Keyfile not found: {}", keyfile.display()).into());
    }

    // Parse PCR indices
    let pcr_indices: Vec<u8> = pcrs
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .filter(|&p| p < 24)
        .collect();

    if pcr_indices.is_empty() {
        return Err("No valid PCR indices specified".into());
    }

    eprintln!("Enrolling TPM with PCRs: {:?}", pcr_indices);
    eprintln!();

    // Need the LUKS passphrase to seal
    eprintln!("Enter the LUKS passphrase to seal with TPM:");
    let luks_pass = prompt_password("LUKS passphrase: ")?;

    // Also need the Tesseract password to verify keyfile access
    let password = prompt_password("Tesseract password: ")?;

    // Verify the password works
    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;
    let recovered = keyfile_obj.unlock(&password)?;

    // Verify the LUKS passphrase matches
    if recovered.as_str() != luks_pass {
        return Err("LUKS passphrase does not match the one stored in the keyfile".into());
    }

    // Reload and enroll TPM
    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;
    keyfile_obj.enroll_tpm(&luks_pass, &pcr_indices)?;
    keyfile_obj.save(&keyfile)?;

    eprintln!();
    eprintln!("✓ TPM enrollment successful");
    eprintln!("✓ Bound to PCRs: {:?}", pcr_indices);
    eprintln!();
    eprintln!("You can now use 'unlock-tpm' for passwordless unlock");

    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_set_duress(keyfile: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use rpassword::prompt_password;

    if !keyfile.exists() {
        return Err(format!("Keyfile not found: {}", keyfile.display()).into());
    }

    eprintln!("Setting duress password");
    eprintln!();
    eprintln!("WARNING: When the duress password is entered, ALL key material");
    eprintln!("will be destroyed and the keyfile will become permanently unusable.");
    eprintln!("The error message will be indistinguishable from a wrong password.");
    eprintln!();

    // Verify access first
    let password = prompt_password("Tesseract password: ")?;
    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;
    keyfile_obj.unlock(&password)?;

    // Now reload fresh and set duress
    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;

    eprintln!();
    let duress = prompt_password("New duress password: ")?;
    let duress_confirm = prompt_password("Confirm duress password: ")?;

    if duress != duress_confirm {
        return Err("Duress passwords do not match".into());
    }

    if duress == password {
        return Err("Duress password cannot be the same as the Tesseract password".into());
    }

    if duress.len() < 4 {
        return Err("Duress password must be at least 4 characters".into());
    }

    keyfile_obj.set_duress_password(&duress)?;
    keyfile_obj.save(&keyfile)?;

    eprintln!();
    eprintln!("✓ Duress password set");
    eprintln!();
    eprintln!("REMEMBER: Using this password will PERMANENTLY destroy the keyfile!");

    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_remove_duress(keyfile: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use rpassword::prompt_password;

    if !keyfile.exists() {
        return Err(format!("Keyfile not found: {}", keyfile.display()).into());
    }

    // Verify access first
    let password = prompt_password("Tesseract password: ")?;
    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;
    keyfile_obj.unlock(&password)?;

    // Reload and remove duress
    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;

    if !keyfile_obj.has_duress() {
        eprintln!("No duress password is currently set");
        return Ok(());
    }

    keyfile_obj.remove_duress_password();
    keyfile_obj.save(&keyfile)?;

    eprintln!("✓ Duress password removed");

    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_info(keyfile: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !keyfile.exists() {
        return Err(format!("Keyfile not found: {}", keyfile.display()).into());
    }

    let keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;
    let flags = keyfile_obj.flags();

    println!("Tesseract LUKS Keyfile: {}", keyfile.display());
    println!();
    println!("Features:");
    println!(
        "  Post-quantum (ML-KEM-1024): {}",
        if flags.pqc_enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "  TPM auto-unlock:            {}",
        if flags.tpm_enabled {
            "Enrolled"
        } else {
            "Not enrolled"
        }
    );
    println!(
        "  Duress password:            {}",
        if flags.duress_enabled {
            "Configured"
        } else {
            "Not set"
        }
    );
    println!(
        "  YubiKey 2FA:                {}",
        if flags.yubikey_enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_change_password(keyfile: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use rpassword::prompt_password;

    if !keyfile.exists() {
        return Err(format!("Keyfile not found: {}", keyfile.display()).into());
    }

    eprintln!("Changing Tesseract password");
    eprintln!();

    // Get current password and unlock
    let old_password = prompt_password("Current Tesseract password: ")?;
    let mut keyfile_obj = TesseractLuksKeyfile::load(&keyfile)?;
    let luks_pass = keyfile_obj.unlock(&old_password)?;

    eprintln!();

    // Get new password
    let new_password = prompt_password("New Tesseract password: ")?;
    let new_password_confirm = prompt_password("Confirm new Tesseract password: ")?;

    if new_password != new_password_confirm {
        return Err("New passwords do not match".into());
    }

    if new_password.len() < 8 {
        return Err("New password must be at least 8 characters".into());
    }

    // Create new keyfile with same config
    let old_flags = keyfile_obj.flags();
    let config = LuksConfig {
        enable_pqc: old_flags.pqc_enabled,
        enable_tpm: false, // TPM needs re-enrollment
        enable_yubikey: old_flags.yubikey_enabled,
        ..Default::default()
    };

    let new_keyfile = TesseractLuksKeyfile::new(luks_pass.as_str(), &new_password, config)?;
    new_keyfile.save(&keyfile)?;

    eprintln!();
    eprintln!("✓ Password changed successfully");

    if old_flags.tpm_enabled {
        eprintln!();
        eprintln!("Note: TPM enrollment has been reset. Re-enroll with:");
        eprintln!("  tesseract-luks enroll-tpm {}", keyfile.display());
    }

    if old_flags.duress_enabled {
        eprintln!();
        eprintln!("Note: Duress password has been reset. Re-configure with:");
        eprintln!("  tesseract-luks set-duress {}", keyfile.display());
    }

    Ok(())
}
