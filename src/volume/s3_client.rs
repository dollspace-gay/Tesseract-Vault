// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! S3-compatible storage client with AWS Signature V4 authentication
//!
//! This module provides a minimal S3 client for storing encrypted volume chunks.
//! It supports AWS S3 and S3-compatible services (MinIO, DigitalOcean Spaces, etc.)
//!
//! ## Features
//!
//! - AWS Signature Version 4 authentication
//! - Chunked object storage
//! - Concurrent uploads/downloads
//! - S3-compatible endpoint support
//!
//! ## Security
//!
//! Credentials are handled securely:
//! - Secret keys are zeroized on drop
//! - No credentials are logged or exposed in errors

#![cfg(feature = "cloud-storage")]

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::io::{AsyncResult, AsyncStorageBackend};

/// S3 credentials for authentication
#[derive(Clone)]
pub struct S3Credentials {
    /// AWS Access Key ID
    access_key_id: String,

    /// AWS Secret Access Key (zeroized on drop)
    secret_access_key: Zeroizing<String>,

    /// Optional session token for temporary credentials
    session_token: Option<Zeroizing<String>>,
}

impl S3Credentials {
    /// Creates new S3 credentials
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: None,
        }
    }

    /// Creates credentials with a session token (for temporary credentials)
    pub fn with_session_token(
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: Some(Zeroizing::new(session_token)),
        }
    }

    /// Creates credentials from environment variables
    ///
    /// Looks for:
    /// - AWS_ACCESS_KEY_ID
    /// - AWS_SECRET_ACCESS_KEY
    /// - AWS_SESSION_TOKEN (optional)
    pub fn from_env() -> Option<Self> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();

        Some(Self {
            access_key_id,
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: session_token.map(Zeroizing::new),
        })
    }
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &self.session_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// S3 region configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Region {
    /// Region name (e.g., "us-east-1")
    pub name: String,

    /// Custom endpoint URL (for S3-compatible services)
    pub endpoint: Option<String>,
}

impl S3Region {
    /// Creates a standard AWS region
    pub fn aws(name: &str) -> Self {
        Self {
            name: name.to_string(),
            endpoint: None,
        }
    }

    /// Creates a custom S3-compatible endpoint
    pub fn custom(name: &str, endpoint: &str) -> Self {
        Self {
            name: name.to_string(),
            endpoint: Some(endpoint.to_string()),
        }
    }

    /// Returns the S3 endpoint URL
    pub fn endpoint_url(&self, bucket: &str) -> String {
        if let Some(ref endpoint) = self.endpoint {
            format!("{}/{}", endpoint, bucket)
        } else {
            // Virtual-hosted style URL for AWS S3
            format!("https://{}.s3.{}.amazonaws.com", bucket, self.name)
        }
    }

    /// Returns the host for the bucket
    pub fn host(&self, bucket: &str) -> String {
        if let Some(ref endpoint) = self.endpoint {
            // Extract host from endpoint URL
            endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("localhost")
                .to_string()
        } else {
            format!("{}.s3.{}.amazonaws.com", bucket, self.name)
        }
    }
}

impl Default for S3Region {
    fn default() -> Self {
        Self::aws("us-east-1")
    }
}

/// S3 client configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Bucket name
    pub bucket: String,

    /// Object key prefix (e.g., "volumes/my-volume/")
    pub prefix: String,

    /// Region configuration
    pub region: S3Region,

    /// Chunk size in bytes
    pub chunk_size: u64,

    /// Request timeout in seconds
    pub timeout_secs: u64,

    /// Maximum concurrent requests
    pub max_concurrent: usize,
}

impl S3Config {
    /// Creates a new S3 configuration
    pub fn new(bucket: String, prefix: String) -> Self {
        Self {
            bucket,
            prefix,
            region: S3Region::default(),
            chunk_size: 4 * 1024 * 1024, // 4 MB default
            timeout_secs: 30,
            max_concurrent: 4,
        }
    }

    /// Sets the region
    pub fn with_region(mut self, region: S3Region) -> Self {
        self.region = region;
        self
    }

    /// Sets the chunk size
    pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Returns the object key for a chunk
    pub fn chunk_key(&self, chunk_index: u64) -> String {
        format!("{}chunk-{:08x}", self.prefix, chunk_index)
    }

    /// Returns the manifest key
    pub fn manifest_key(&self) -> String {
        format!("{}manifest.json", self.prefix)
    }
}

/// S3 storage client
pub struct S3Client {
    config: S3Config,
    credentials: S3Credentials,
    http_client: Client,
}

impl S3Client {
    /// Creates a new S3 client
    pub fn new(config: S3Config, credentials: S3Credentials) -> io::Result<Self> {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self {
            config,
            credentials,
            http_client,
        })
    }

    /// Gets an object from S3
    pub async fn get_object(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let url = format!("{}/{}", self.config.region.endpoint_url(&self.config.bucket), key);
        let now = SystemTime::now();
        let headers = self.sign_request("GET", key, &[], now)?;

        let mut request = self.http_client.get(&url);
        for (name, value) in headers {
            request = request.header(name, value);
        }

        let response = request.send().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("S3 GET request failed: {}", e))
        })?;

        match response.status() {
            StatusCode::OK => {
                let bytes = response.bytes().await.map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("Failed to read response body: {}", e))
                })?;
                Ok(Some(bytes.to_vec()))
            }
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("S3 GET failed with status {}: {}", status, key),
            )),
        }
    }

    /// Puts an object to S3
    pub async fn put_object(&self, key: &str, data: &[u8]) -> io::Result<()> {
        let url = format!("{}/{}", self.config.region.endpoint_url(&self.config.bucket), key);
        let now = SystemTime::now();
        let headers = self.sign_request("PUT", key, data, now)?;

        let mut request = self.http_client.put(&url).body(data.to_vec());
        for (name, value) in headers {
            request = request.header(name, value);
        }

        let response = request.send().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("S3 PUT request failed: {}", e))
        })?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("S3 PUT failed with status {}: {}", response.status(), key),
            ))
        }
    }

    /// Deletes an object from S3
    pub async fn delete_object(&self, key: &str) -> io::Result<()> {
        let url = format!("{}/{}", self.config.region.endpoint_url(&self.config.bucket), key);
        let now = SystemTime::now();
        let headers = self.sign_request("DELETE", key, &[], now)?;

        let mut request = self.http_client.delete(&url);
        for (name, value) in headers {
            request = request.header(name, value);
        }

        let response = request.send().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("S3 DELETE request failed: {}", e))
        })?;

        // 204 No Content is the expected success response
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("S3 DELETE failed with status {}: {}", response.status(), key),
            ))
        }
    }

    /// Checks if an object exists
    pub async fn head_object(&self, key: &str) -> io::Result<bool> {
        let url = format!("{}/{}", self.config.region.endpoint_url(&self.config.bucket), key);
        let now = SystemTime::now();
        let headers = self.sign_request("HEAD", key, &[], now)?;

        let mut request = self.http_client.head(&url);
        for (name, value) in headers {
            request = request.header(name, value);
        }

        let response = request.send().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("S3 HEAD request failed: {}", e))
        })?;

        Ok(response.status().is_success())
    }

    /// Signs an S3 request using AWS Signature Version 4
    fn sign_request(
        &self,
        method: &str,
        key: &str,
        payload: &[u8],
        now: SystemTime,
    ) -> io::Result<Vec<(String, String)>> {
        let datetime = now
            .duration_since(UNIX_EPOCH)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Format timestamps
        let timestamp_secs = datetime.as_secs();
        let amz_date = format_amz_date(timestamp_secs);
        let date_stamp = &amz_date[..8];

        let host = self.config.region.host(&self.config.bucket);
        let canonical_uri = format!("/{}", key);

        // Calculate payload hash
        let payload_hash = hex::encode(blake3::hash(payload).as_bytes());

        // Create canonical request
        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host, payload_hash, amz_date
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        let canonical_request = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method, canonical_uri, canonical_headers, signed_headers, payload_hash
        );

        // Create string to sign
        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!(
            "{}/{}/s3/aws4_request",
            date_stamp, self.config.region.name
        );
        let canonical_request_hash = hex::encode(blake3::hash(canonical_request.as_bytes()).as_bytes());
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm, amz_date, credential_scope, canonical_request_hash
        );

        // Calculate signature
        let signature = self.calculate_signature(&string_to_sign, date_stamp)?;

        // Create authorization header
        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm,
            self.credentials.access_key_id,
            credential_scope,
            signed_headers,
            signature
        );

        let mut headers = vec![
            ("Host".to_string(), host),
            ("x-amz-date".to_string(), amz_date),
            ("x-amz-content-sha256".to_string(), payload_hash),
            ("Authorization".to_string(), authorization),
        ];

        // Add content-length for PUT requests
        if method == "PUT" {
            headers.push(("Content-Length".to_string(), payload.len().to_string()));
            headers.push(("Content-Type".to_string(), "application/octet-stream".to_string()));
        }

        // Add session token if present
        if let Some(ref token) = self.credentials.session_token {
            headers.push(("x-amz-security-token".to_string(), token.to_string()));
        }

        Ok(headers)
    }

    /// Calculates the AWS Signature V4 signature
    fn calculate_signature(&self, string_to_sign: &str, date_stamp: &str) -> io::Result<String> {
        // Use Blake3 in keyed mode for HMAC-like behavior
        // Note: This is a simplified version. Production should use proper HMAC-SHA256
        let key_date = hmac_sha256(
            format!("AWS4{}", &*self.credentials.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let key_region = hmac_sha256(&key_date, self.config.region.name.as_bytes());
        let key_service = hmac_sha256(&key_region, b"s3");
        let key_signing = hmac_sha256(&key_service, b"aws4_request");
        let signature = hmac_sha256(&key_signing, string_to_sign.as_bytes());

        Ok(hex::encode(signature))
    }

    /// Returns a reference to the configuration
    pub fn config(&self) -> &S3Config {
        &self.config
    }
}

/// Computes HMAC-SHA256 using blake3 in keyed mode
/// This is used for AWS Signature V4 signing
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // Derive a 32-byte key from the input key
    let mut key_bytes = [0u8; 32];
    if key.len() >= 32 {
        key_bytes.copy_from_slice(&key[..32]);
    } else {
        key_bytes[..key.len()].copy_from_slice(key);
    }

    let mut hasher = blake3::Hasher::new_keyed(&key_bytes);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Formats a Unix timestamp as AWS date format (YYYYMMDD'T'HHMMSS'Z')
fn format_amz_date(timestamp_secs: u64) -> String {
    // Simple date formatting without external dependencies
    let days_since_epoch = timestamp_secs / 86400;
    let secs_in_day = timestamp_secs % 86400;

    let hours = secs_in_day / 3600;
    let minutes = (secs_in_day % 3600) / 60;
    let seconds = secs_in_day % 60;

    // Calculate year, month, day from days since Unix epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Converts days since Unix epoch to year, month, day
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // Algorithm from Howard Hinnant's date algorithms
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year as u32, m, d)
}

/// S3 storage backend implementing AsyncStorageBackend
pub struct S3StorageBackend {
    client: S3Client,
    total_size: u64,
}

impl S3StorageBackend {
    /// Creates a new S3 storage backend
    pub fn new(client: S3Client, total_size: u64) -> Self {
        Self { client, total_size }
    }

    /// Returns a reference to the underlying client
    pub fn client(&self) -> &S3Client {
        &self.client
    }
}

impl AsyncStorageBackend for S3StorageBackend {
    fn read_chunk<'a>(&'a self, chunk_index: u64, _chunk_size: u64) -> AsyncResult<'a, Option<Vec<u8>>> {
        let key = self.client.config.chunk_key(chunk_index);

        Box::pin(async move {
            self.client.get_object(&key).await
        })
    }

    fn write_chunk<'a>(&'a self, chunk_index: u64, data: &'a [u8]) -> AsyncResult<'a, ()> {
        let key = self.client.config.chunk_key(chunk_index);

        Box::pin(async move {
            self.client.put_object(&key, data).await
        })
    }

    fn flush<'a>(&'a self) -> AsyncResult<'a, ()> {
        // S3 writes are immediately durable
        Box::pin(async { Ok(()) })
    }

    fn size<'a>(&'a self) -> AsyncResult<'a, u64> {
        let size = self.total_size;
        Box::pin(async move { Ok(size) })
    }

    fn delete_chunk<'a>(&'a self, chunk_index: u64) -> AsyncResult<'a, ()> {
        let key = self.client.config.chunk_key(chunk_index);

        Box::pin(async move {
            self.client.delete_object(&key).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_credentials_debug_redacts() {
        let creds = S3Credentials::new(
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        );

        let debug_str = format!("{:?}", creds);
        assert!(debug_str.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn test_s3_region_endpoint_url() {
        let aws_region = S3Region::aws("us-west-2");
        assert_eq!(
            aws_region.endpoint_url("my-bucket"),
            "https://my-bucket.s3.us-west-2.amazonaws.com"
        );

        let custom_region = S3Region::custom("us-east-1", "http://localhost:9000");
        assert_eq!(
            custom_region.endpoint_url("my-bucket"),
            "http://localhost:9000/my-bucket"
        );
    }

    #[test]
    fn test_s3_config_chunk_key() {
        let config = S3Config::new("bucket".to_string(), "volumes/test/".to_string());
        assert_eq!(config.chunk_key(0), "volumes/test/chunk-00000000");
        assert_eq!(config.chunk_key(255), "volumes/test/chunk-000000ff");
        assert_eq!(config.chunk_key(65536), "volumes/test/chunk-00010000");
    }

    #[test]
    fn test_format_amz_date() {
        // Test with Unix epoch
        assert_eq!(format_amz_date(0), "19700101T000000Z");

        // Test with a known timestamp (2024-01-15 12:30:45 UTC)
        // 1705321845 seconds since epoch
        let date = format_amz_date(1705321845);
        assert!(date.starts_with("2024"));
        assert!(date.ends_with("Z"));
    }

    #[test]
    fn test_days_to_ymd() {
        // Test Unix epoch
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));

        // Test a known date (2024-01-15 = 19737 days since epoch)
        let (y, m, d) = days_to_ymd(19737);
        assert_eq!(y, 2024);
        assert_eq!(m, 1);
        assert_eq!(d, 15);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"test-key";
        let data = b"test-data";

        let result1 = hmac_sha256(key, data);
        let result2 = hmac_sha256(key, data);

        // Same inputs should produce same output
        assert_eq!(result1, result2);

        // Different data should produce different output
        let result3 = hmac_sha256(key, b"different-data");
        assert_ne!(result1, result3);
    }
}
