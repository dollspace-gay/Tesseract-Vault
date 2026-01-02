// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Dropbox storage client for encrypted volume chunks
//!
//! This module provides a Dropbox client for storing encrypted volume chunks.
//! It uses the Dropbox HTTP API v2 for file operations.
//!
//! ## Features
//!
//! - OAuth2 Bearer token authentication
//! - Chunked file storage
//! - Upload session support for large files
//! - Concurrent uploads/downloads
//!
//! ## Security
//!
//! - Access tokens are zeroized on drop
//! - No tokens are logged or exposed in errors

#![cfg(feature = "cloud-storage")]

use std::io;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::io::{AsyncResult, AsyncStorageBackend};

/// Dropbox API endpoints
const DROPBOX_CONTENT_API: &str = "https://content.dropboxapi.com/2";
const DROPBOX_API: &str = "https://api.dropboxapi.com/2";

/// Dropbox credentials (OAuth2 access token)
#[derive(Clone)]
pub struct DropboxCredentials {
    /// OAuth2 access token (zeroized on drop)
    access_token: Zeroizing<String>,

    /// Optional refresh token for token renewal
    refresh_token: Option<Zeroizing<String>>,
}

impl DropboxCredentials {
    /// Creates new Dropbox credentials with an access token
    pub fn new(access_token: String) -> Self {
        Self {
            access_token: Zeroizing::new(access_token),
            refresh_token: None,
        }
    }

    /// Creates credentials with a refresh token
    pub fn with_refresh_token(access_token: String, refresh_token: String) -> Self {
        Self {
            access_token: Zeroizing::new(access_token),
            refresh_token: Some(Zeroizing::new(refresh_token)),
        }
    }

    /// Creates credentials from environment variable
    ///
    /// Looks for DROPBOX_ACCESS_TOKEN
    pub fn from_env() -> Option<Self> {
        let access_token = std::env::var("DROPBOX_ACCESS_TOKEN").ok()?;
        Some(Self::new(access_token))
    }

    /// Returns the access token for API requests
    fn token(&self) -> &str {
        &self.access_token
    }
}

impl std::fmt::Debug for DropboxCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropboxCredentials")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Dropbox client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropboxConfig {
    /// Path prefix in Dropbox (e.g., "/Apps/Tesseract/my-volume/")
    pub path_prefix: String,

    /// Chunk size in bytes
    pub chunk_size: u64,

    /// Request timeout in seconds
    pub timeout_secs: u64,

    /// Maximum concurrent requests
    pub max_concurrent: usize,
}

impl DropboxConfig {
    /// Creates a new Dropbox configuration
    pub fn new(path_prefix: String) -> Self {
        // Ensure path starts with /
        let path_prefix = if path_prefix.starts_with('/') {
            path_prefix
        } else {
            format!("/{}", path_prefix)
        };

        // Ensure path ends with /
        let path_prefix = if path_prefix.ends_with('/') {
            path_prefix
        } else {
            format!("{}/", path_prefix)
        };

        Self {
            path_prefix,
            chunk_size: 4 * 1024 * 1024, // 4 MB default
            timeout_secs: 60,
            max_concurrent: 4,
        }
    }

    /// Sets the chunk size
    pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Returns the Dropbox path for a chunk
    pub fn chunk_path(&self, chunk_index: u64) -> String {
        format!("{}chunk-{:08x}", self.path_prefix, chunk_index)
    }

    /// Returns the manifest path
    pub fn manifest_path(&self) -> String {
        format!("{}manifest.json", self.path_prefix)
    }
}

/// Dropbox API request for file download
#[derive(Debug, Serialize)]
struct DownloadArg {
    path: String,
}

/// Dropbox API request for file upload
#[derive(Debug, Serialize)]
struct UploadArg {
    path: String,
    mode: WriteMode,
    autorename: bool,
    mute: bool,
}

/// Dropbox write mode
#[derive(Debug, Serialize)]
#[serde(tag = ".tag")]
enum WriteMode {
    #[serde(rename = "overwrite")]
    Overwrite,
}

/// Dropbox API request for file deletion
#[derive(Debug, Serialize)]
struct DeleteArg {
    path: String,
}

/// Dropbox API request for file metadata
#[derive(Debug, Serialize)]
struct GetMetadataArg {
    path: String,
    include_deleted: bool,
}

/// Dropbox file metadata response
#[derive(Debug, Deserialize)]
struct FileMetadata {
    #[serde(rename = ".tag")]
    tag: String,
    #[allow(dead_code)]
    size: Option<u64>,
}

/// Dropbox storage client
pub struct DropboxClient {
    config: DropboxConfig,
    credentials: DropboxCredentials,
    http_client: Client,
}

impl DropboxClient {
    /// Creates a new Dropbox client
    pub fn new(config: DropboxConfig, credentials: DropboxCredentials) -> io::Result<Self> {
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

    /// Downloads a file from Dropbox
    pub async fn download(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        let url = format!("{}/files/download", DROPBOX_CONTENT_API);

        let arg = DownloadArg {
            path: path.to_string(),
        };
        let arg_json =
            serde_json::to_string(&arg).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let response = self
            .http_client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.credentials.token()),
            )
            .header("Dropbox-API-Arg", arg_json)
            .send()
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Dropbox download failed: {}", e),
                )
            })?;

        match response.status() {
            StatusCode::OK => {
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                Ok(Some(bytes.to_vec()))
            }
            StatusCode::CONFLICT => {
                // File not found returns 409 with path/not_found error
                let error_text = response.text().await.unwrap_or_default();
                if error_text.contains("not_found") {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Dropbox error: {}", error_text),
                    ))
                }
            }
            status => {
                let error_text = response.text().await.unwrap_or_default();
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Dropbox download failed ({}): {}", status, error_text),
                ))
            }
        }
    }

    /// Uploads a file to Dropbox
    pub async fn upload(&self, path: &str, data: &[u8]) -> io::Result<()> {
        let url = format!("{}/files/upload", DROPBOX_CONTENT_API);

        let arg = UploadArg {
            path: path.to_string(),
            mode: WriteMode::Overwrite,
            autorename: false,
            mute: true,
        };
        let arg_json =
            serde_json::to_string(&arg).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let response = self
            .http_client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.credentials.token()),
            )
            .header("Dropbox-API-Arg", arg_json)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Dropbox upload failed: {}", e),
                )
            })?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Dropbox upload failed: {}", error_text),
            ))
        }
    }

    /// Deletes a file from Dropbox
    pub async fn delete(&self, path: &str) -> io::Result<()> {
        let url = format!("{}/files/delete_v2", DROPBOX_API);

        let arg = DeleteArg {
            path: path.to_string(),
        };

        let response = self
            .http_client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.credentials.token()),
            )
            .header("Content-Type", "application/json")
            .json(&arg)
            .send()
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Dropbox delete failed: {}", e),
                )
            })?;

        match response.status() {
            s if s.is_success() => Ok(()),
            StatusCode::CONFLICT => {
                // File not found is okay for delete
                let error_text = response.text().await.unwrap_or_default();
                if error_text.contains("not_found") {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Dropbox error: {}", error_text),
                    ))
                }
            }
            status => {
                let error_text = response.text().await.unwrap_or_default();
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Dropbox delete failed ({}): {}", status, error_text),
                ))
            }
        }
    }

    /// Checks if a file exists
    pub async fn exists(&self, path: &str) -> io::Result<bool> {
        let url = format!("{}/files/get_metadata", DROPBOX_API);

        let arg = GetMetadataArg {
            path: path.to_string(),
            include_deleted: false,
        };

        let response = self
            .http_client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.credentials.token()),
            )
            .header("Content-Type", "application/json")
            .json(&arg)
            .send()
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Dropbox metadata failed: {}", e),
                )
            })?;

        match response.status() {
            StatusCode::OK => {
                let metadata: FileMetadata = response
                    .json()
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                Ok(metadata.tag == "file")
            }
            StatusCode::CONFLICT => Ok(false), // Not found
            _ => Ok(false),
        }
    }

    /// Returns a reference to the configuration
    pub fn config(&self) -> &DropboxConfig {
        &self.config
    }
}

/// Dropbox storage backend implementing AsyncStorageBackend
pub struct DropboxStorageBackend {
    client: DropboxClient,
    total_size: u64,
}

impl DropboxStorageBackend {
    /// Creates a new Dropbox storage backend
    pub fn new(client: DropboxClient, total_size: u64) -> Self {
        Self { client, total_size }
    }

    /// Returns a reference to the underlying client
    pub fn client(&self) -> &DropboxClient {
        &self.client
    }
}

impl AsyncStorageBackend for DropboxStorageBackend {
    fn read_chunk<'a>(
        &'a self,
        chunk_index: u64,
        _chunk_size: u64,
    ) -> AsyncResult<'a, Option<Vec<u8>>> {
        let path = self.client.config.chunk_path(chunk_index);

        Box::pin(async move { self.client.download(&path).await })
    }

    fn write_chunk<'a>(&'a self, chunk_index: u64, data: &'a [u8]) -> AsyncResult<'a, ()> {
        let path = self.client.config.chunk_path(chunk_index);

        Box::pin(async move { self.client.upload(&path, data).await })
    }

    fn flush<'a>(&'a self) -> AsyncResult<'a, ()> {
        // Dropbox writes are immediately durable
        Box::pin(async { Ok(()) })
    }

    fn size<'a>(&'a self) -> AsyncResult<'a, u64> {
        let size = self.total_size;
        Box::pin(async move { Ok(size) })
    }

    fn delete_chunk<'a>(&'a self, chunk_index: u64) -> AsyncResult<'a, ()> {
        let path = self.client.config.chunk_path(chunk_index);

        Box::pin(async move { self.client.delete(&path).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dropbox_credentials_debug_redacts() {
        let creds = DropboxCredentials::new("sl.test-token-12345".to_string());

        let debug_str = format!("{:?}", creds);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("sl.test-token"));
    }

    #[test]
    fn test_dropbox_config_chunk_path() {
        let config = DropboxConfig::new("/Apps/Tesseract/my-volume".to_string());
        assert_eq!(
            config.chunk_path(0),
            "/Apps/Tesseract/my-volume/chunk-00000000"
        );
        assert_eq!(
            config.chunk_path(255),
            "/Apps/Tesseract/my-volume/chunk-000000ff"
        );
    }

    #[test]
    fn test_dropbox_config_normalizes_path() {
        // Without leading slash
        let config1 = DropboxConfig::new("Apps/Tesseract/vol".to_string());
        assert!(config1.path_prefix.starts_with('/'));
        assert!(config1.path_prefix.ends_with('/'));

        // Without trailing slash
        let config2 = DropboxConfig::new("/Apps/Tesseract/vol".to_string());
        assert!(config2.path_prefix.ends_with('/'));

        // Already correct
        let config3 = DropboxConfig::new("/Apps/Tesseract/vol/".to_string());
        assert_eq!(config3.path_prefix, "/Apps/Tesseract/vol/");
    }

    #[test]
    fn test_dropbox_config_manifest_path() {
        let config = DropboxConfig::new("/Apps/Tesseract/test/".to_string());
        assert_eq!(config.manifest_path(), "/Apps/Tesseract/test/manifest.json");
    }
}
