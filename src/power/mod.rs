// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Power state monitoring module
//!
//! Monitors system power events (suspend, hibernate, shutdown) to ensure
//! encrypted volumes are safely unmounted before power state transitions.

use thiserror::Error;

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

/// Power events that can trigger callbacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// System is about to suspend
    Suspend,

    /// System is about to hibernate
    Hibernate,

    /// System is about to shut down
    Shutdown,

    /// System is resuming from suspend/hibernate
    Resume,
}

/// Errors that can occur in power monitoring
#[derive(Debug, Error)]
pub enum PowerMonitorError {
    /// Platform not supported
    #[error("Power monitoring not supported on this platform")]
    PlatformNotSupported,

    /// Failed to register for power events
    #[error("Failed to register for power events: {0}")]
    RegistrationFailed(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Power monitor error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PowerMonitorError>;

/// Callback function type for power events
pub type PowerCallback = Box<dyn Fn(PowerEvent) + Send + Sync>;

/// Power state monitor
///
/// Monitors system power events and triggers callbacks when power state changes.
/// This allows for graceful handling of suspend/hibernate/shutdown events.
///
/// # Example
///
/// ```no_run
/// use tesseract_lib::power::{PowerMonitor, PowerEvent};
///
/// let mut monitor = PowerMonitor::new();
///
/// monitor.register_callback(Box::new(move |event| {
///     match event {
///         PowerEvent::Suspend | PowerEvent::Hibernate | PowerEvent::Shutdown => {
///             println!("System power event: {:?} - unmounting volumes", event);
///             // Unmount all volumes here
///         }
///         PowerEvent::Resume => {
///             println!("System resumed");
///         }
///     }
/// }));
///
/// monitor.start().expect("Failed to start power monitor");
/// ```
pub struct PowerMonitor {
    #[cfg(windows)]
    inner: windows::WindowsPowerMonitor,

    #[cfg(target_os = "linux")]
    inner: linux::LinuxPowerMonitor,

    #[cfg(not(any(windows, target_os = "linux")))]
    _phantom: std::marker::PhantomData<()>,
}

impl PowerMonitor {
    /// Creates a new power monitor
    pub fn new() -> Self {
        #[cfg(windows)]
        {
            Self {
                inner: windows::WindowsPowerMonitor::new(),
            }
        }

        #[cfg(target_os = "linux")]
        {
            Self {
                inner: linux::LinuxPowerMonitor::new(),
            }
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    /// Registers a callback to be called on power events
    pub fn register_callback(&mut self, callback: PowerCallback) {
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.register_callback(callback);
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = callback;
        }
    }

    /// Starts monitoring power events
    pub fn start(&mut self) -> Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.start()
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Err(PowerMonitorError::PlatformNotSupported)
        }
    }

    /// Stops monitoring power events
    pub fn stop(&mut self) -> Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.stop()
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Err(PowerMonitorError::PlatformNotSupported)
        }
    }
}

impl Default for PowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_event_variants() {
        // Test PartialEq
        assert_eq!(PowerEvent::Suspend, PowerEvent::Suspend);
        assert_eq!(PowerEvent::Hibernate, PowerEvent::Hibernate);
        assert_eq!(PowerEvent::Shutdown, PowerEvent::Shutdown);
        assert_eq!(PowerEvent::Resume, PowerEvent::Resume);

        // Test inequality
        assert_ne!(PowerEvent::Suspend, PowerEvent::Resume);
        assert_ne!(PowerEvent::Hibernate, PowerEvent::Shutdown);
    }

    #[test]
    fn test_power_event_clone() {
        let event = PowerEvent::Suspend;
        let cloned = event;
        assert_eq!(event, cloned);
    }

    #[test]
    fn test_power_event_debug() {
        let event = PowerEvent::Suspend;
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("Suspend"));
    }

    #[test]
    fn test_power_monitor_error_display() {
        let err = PowerMonitorError::PlatformNotSupported;
        assert!(err.to_string().contains("not supported"));

        let err = PowerMonitorError::RegistrationFailed("test failure".to_string());
        assert!(err.to_string().contains("Failed to register"));
        assert!(err.to_string().contains("test failure"));

        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "io test");
        let err = PowerMonitorError::Io(io_err);
        assert!(err.to_string().contains("I/O error"));

        let err = PowerMonitorError::Other("custom error".to_string());
        assert!(err.to_string().contains("Power monitor error"));
        assert!(err.to_string().contains("custom error"));
    }

    #[test]
    fn test_power_monitor_new() {
        let _monitor = PowerMonitor::new();
    }

    #[test]
    fn test_power_monitor_default() {
        let _monitor = PowerMonitor::default();
    }

    #[test]
    fn test_power_monitor_io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let monitor_err: PowerMonitorError = io_err.into();
        assert!(matches!(monitor_err, PowerMonitorError::Io(_)));
    }
}
