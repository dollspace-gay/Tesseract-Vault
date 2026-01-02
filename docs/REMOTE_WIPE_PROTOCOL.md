# Remote Wipe Protocol

This document describes Tesseract Vault's remote wipe functionality for cloud-synced volumes.

## Overview

Remote wipe enables secure destruction of encryption keys across all devices when triggered via cloud sync. This provides protection against device loss or theft by allowing you to remotely destroy the keys needed to decrypt your data.

## Security Model

The remote wipe protocol is designed with defense-in-depth:

1. **Token-based authentication**: Wipe commands require a secret token generated at setup
2. **HMAC signatures**: Commands are cryptographically signed with Blake3
3. **Replay protection**: Commands include timestamps and nonces
4. **Rate limiting**: Prevents brute force attacks on the token
5. **Lockout**: Automatic lockout after repeated failures

## Protocol Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `WIPE_TOKEN_SIZE` | 32 bytes (256 bits) | Token entropy |
| `TOKEN_SALT_SIZE` | 16 bytes | Salt for token hash |
| `COMMAND_NONCE_SIZE` | 16 bytes | Replay protection |
| `MAX_COMMAND_AGE_SECS` | 300 (5 minutes) | Command expiry |
| `RATE_LIMIT_SECS` | 5 seconds | Minimum between attempts |
| `MAX_FAILED_ATTEMPTS` | 5 | Before lockout |
| `LOCKOUT_DURATION_SECS` | 3600 (1 hour) | Lockout duration |

## Command Types

### DestroyKeys

Immediately and irreversibly destroys all encryption keys:

- Secure overwrites keyfiles with random data
- Zeroizes in-memory key material
- Volume becomes permanently inaccessible

```rust
WipeCommandType::DestroyKeys
```

### Lock

Temporarily locks the volume without destroying keys:

- Keys remain on disk but are marked inaccessible
- Requires re-authentication to unlock
- Reversible operation

```rust
WipeCommandType::Lock
```

### CheckIn

Request device acknowledgment (for dead man's switch):

- Device confirms it's online and accessible
- No keys are affected
- Used for activity monitoring

```rust
WipeCommandType::CheckIn
```

### RevokeToken

Revokes the current wipe token:

- Old token immediately becomes invalid
- Requires token regeneration to enable wipe again
- Use after suspected token compromise

```rust
WipeCommandType::RevokeToken
```

## Data Structures

### WipeToken

The secret token used to authenticate wipe commands:

```rust
pub struct WipeToken {
    token: [u8; WIPE_TOKEN_SIZE],  // 32 bytes, zeroized on drop
}

impl WipeToken {
    fn generate() -> Self;                          // CSPRNG generation
    fn to_hex(&self) -> Zeroizing<String>;          // Hex encoding
    fn from_hex(hex_str: &str) -> Result<Self>;     // Hex decoding
    fn compute_verification_hash(&self, salt: &[u8; 16]) -> [u8; 32];
    fn sign_command(&self, command: &WipeCommandData) -> [u8; 32];
}
```

### WipeCommand

A signed command ready for transmission:

```rust
pub struct WipeCommand {
    pub data: WipeCommandData,
    pub signature: [u8; 32],  // Blake3 HMAC
}

pub struct WipeCommandData {
    pub volume_id: String,
    pub timestamp: u64,                   // Unix timestamp
    pub nonce: [u8; COMMAND_NONCE_SIZE],  // Random bytes
    pub command_type: WipeCommandType,
    pub message: Option<String>,          // Optional reason
}
```

### StoredWipeConfig

Configuration stored on device (token is NOT stored):

```rust
pub struct StoredWipeConfig {
    pub volume_id: String,
    pub token_salt: [u8; TOKEN_SALT_SIZE],
    pub token_hash: [u8; 32],            // Salted Blake3 hash
    pub enabled: bool,
    pub keyfile_paths: Vec<String>,
    pub require_confirmation: bool,
    pub failed_attempts: u32,
    pub last_attempt: u64,
    pub lockout_until: u64,
    pub used_nonces: Vec<[u8; COMMAND_NONCE_SIZE]>,
}
```

## Authentication Flow

### Token Verification

```
1. Client provides: token (32 bytes)
2. Server has: salt (16 bytes), stored_hash (32 bytes)

3. Compute: hash = Blake3(salt || token || "tesseract-wipe-verification")
4. Compare: hash == stored_hash (constant-time)
5. Accept if match, reject otherwise
```

### Command Signature

```
1. Build data: volume_id || timestamp || nonce || command_type
2. Compute: signature = Blake3(token || data || "tesseract-wipe-command")
3. Attach signature to command
4. Receiver verifies using stored token hash
```

## Usage

### Initial Setup

```rust
use tesseract_lib::volume::remote_wipe::{RemoteWipeManager, WipeToken};

// Generate token and create manager
let (mut manager, token) = RemoteWipeManager::new("my-volume-id");

// CRITICAL: Store this token securely - it cannot be recovered!
println!("Wipe token: {}", token.to_hex().as_str());

// Configure keyfiles to destroy
manager.add_keyfile_path("/path/to/volume.keyfile");
manager.add_keyfile_path("/path/to/recovery.key");

// Optionally require confirmation
manager.set_require_confirmation(true);

// Save configuration
manager.save(Path::new("/etc/tesseract/wipe.conf"))?;
```

### Sending a Wipe Command

```rust
use tesseract_lib::volume::remote_wipe::{WipeCommand, WipeCommandType, WipeToken};

// Load the stored token
let token = WipeToken::from_hex("your_stored_hex_token")?;

// Create signed command
let command = WipeCommand::new(&token, "my-volume-id", WipeCommandType::DestroyKeys);

// Or with a message
let command = WipeCommand::with_message(
    &token,
    "my-volume-id",
    WipeCommandType::DestroyKeys,
    "Device lost - destroying keys"
);

// Serialize and send via cloud sync
let json = serde_json::to_string(&command)?;
cloud_backend.upload("wipe_command.json", &json).await?;
```

### Processing a Wipe Command

```rust
use tesseract_lib::volume::remote_wipe::RemoteWipeManager;

// Load configuration
let mut manager = RemoteWipeManager::load(Path::new("/etc/tesseract/wipe.conf"))?;

// Receive command from cloud
let json = cloud_backend.download("wipe_command.json").await?;
let command: WipeCommand = serde_json::from_str(&json)?;

// Process command
match manager.process_command(&command) {
    Ok(WipeResult::Destroyed { keyfiles_wiped, .. }) => {
        println!("Destroyed {} keyfiles", keyfiles_wiped);
    }
    Ok(WipeResult::ConfirmationRequired { command }) => {
        // User must confirm before execution
        println!("Confirmation required for wipe");
    }
    Err(WipeError::InvalidSignature) => {
        println!("Command authentication failed");
    }
    Err(WipeError::LockedOut) => {
        println!("Too many failed attempts - locked out");
    }
    // ... handle other cases
}
```

### Cloud Sync Integration

```rust
use tesseract_lib::volume::cloud_sync::CloudSyncClient;

// Initialize cloud sync with remote wipe
let mut client = CloudSyncClient::new(s3_backend)?;

// Register wipe config with cloud sync
let (manager, token) = RemoteWipeManager::new(&client.volume_id());
client.register_wipe_config(&manager.config()).await?;

// Check for wipe commands during sync
if let Some(command) = client.check_for_wipe_command().await? {
    manager.process_command(&command)?;
}
```

## Replay Protection

### Timestamp Validation

Commands expire after `MAX_COMMAND_AGE_SECS` (5 minutes):

```rust
fn is_fresh(&self) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Reject commands from the future or too old
    self.data.timestamp <= now &&
        now - self.data.timestamp <= MAX_COMMAND_AGE_SECS
}
```

### Nonce Tracking

Each command includes a random nonce. Used nonces are stored to prevent replay:

```rust
fn check_and_record_nonce(&mut self, nonce: &[u8; 16]) -> bool {
    if self.used_nonces.contains(nonce) {
        return false;  // Replay detected
    }
    self.used_nonces.push(*nonce);
    self.prune_old_nonces();  // Remove expired
    true
}
```

## Rate Limiting & Lockout

### Rate Limiting

Minimum 5 seconds between authentication attempts:

```rust
fn is_rate_limited(&self) -> bool {
    let now = current_timestamp();
    now - self.last_attempt < RATE_LIMIT_SECS
}
```

### Lockout

After 5 failed attempts, account is locked for 1 hour:

```rust
fn is_locked_out(&self) -> bool {
    let now = current_timestamp();
    self.lockout_until > now
}

fn record_failure(&mut self) {
    self.failed_attempts += 1;
    self.last_attempt = current_timestamp();

    if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
        self.lockout_until = current_timestamp() + LOCKOUT_DURATION_SECS;
    }
}
```

## Key Destruction Process

When `DestroyKeys` command executes:

1. **Verify authentication** - Token signature is valid
2. **Check freshness** - Command is within 5 minutes
3. **Check replay** - Nonce hasn't been used
4. **Confirmation** - If required, wait for user confirmation
5. **Destroy keyfiles** - For each registered keyfile path:
   - Open file
   - Overwrite with random data (multiple passes)
   - Sync to disk
   - Delete file
6. **Zeroize memory** - Clear any in-memory keys
7. **Disable wipe** - Prevent further commands
8. **Return result** - Report number of files destroyed

```rust
fn destroy_keyfiles(&self) -> WipeResult {
    let mut wiped = 0;
    for path in &self.config.keyfile_paths {
        if let Ok(_) = secure_delete(path) {
            wiped += 1;
        }
    }
    WipeResult::Destroyed {
        keyfiles_wiped: wiped,
        timestamp: current_timestamp(),
    }
}
```

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `NotEnabled` | Wipe not configured | Call `set_enabled(true)` |
| `InvalidToken` | Wrong token provided | Use correct token |
| `InvalidSignature` | Command tampering detected | Regenerate command |
| `CommandExpired` | Timestamp too old | Create fresh command |
| `VolumeMismatch` | Wrong volume ID | Check volume ID |
| `ReplayDetected` | Command already processed | Create new command |
| `RateLimited` | Too many attempts | Wait 5 seconds |
| `LockedOut` | Max failures exceeded | Wait 1 hour |

## GUI Integration

The Tesseract Vault GUI provides remote wipe management:

```rust
// GUI state for remote wipe
pub struct RemoteWipeState {
    pub enabled: bool,
    pub token_visible: bool,
    pub token_hex: String,
    pub require_confirmation: bool,
    pub keyfile_paths: Vec<String>,
}

// Actions
enum RemoteWipeAction {
    GenerateToken,
    RevokeToken,
    EnableWipe,
    DisableWipe,
    AddKeyfile(String),
    RemoveKeyfile(String),
    TestWipe,  // Dry run
}
```

## Security Considerations

### Token Storage

- **Never store the raw token** - Only the salted hash is stored
- **User must backup token** - It cannot be recovered from the hash
- **Consider hardware storage** - YubiKey, secure enclave, etc.

### Attack Resistance

| Attack | Mitigation |
|--------|-----------|
| Token brute force | Rate limiting + lockout |
| Replay attack | Nonces + timestamps |
| Signature forgery | Blake3 HMAC (256-bit) |
| Timing attack | Constant-time comparison |
| Man-in-middle | End-to-end encryption via cloud |

### Operational Security

1. **Test wipe procedure** before relying on it
2. **Store token separately** from the volume
3. **Consider dead man's switch** for automatic wipe after inactivity
4. **Have recovery keys** in case of accidental wipe
5. **Monitor for wipe commands** in logs

## Integration with Cloud Providers

### S3-Compatible Storage

```rust
let command_path = format!("volumes/{}/wipe_command.json", volume_id);
s3_client.put_object(&command_path, &command_json).await?;
```

### Dropbox

```rust
let command_path = format!("/tesseract/{}/wipe_command.json", volume_id);
dropbox_client.upload(&command_path, &command_json).await?;
```

### Custom Backend

Implement the `CloudBackend` trait with `check_wipe_command()` method.

## References

- [Cloud Sync Implementation](../src/volume/cloud_sync.rs)
- [Remote Wipe Module](../src/volume/remote_wipe.rs)
- [README - Remote Wipe Section](../README.md#advanced-features)
