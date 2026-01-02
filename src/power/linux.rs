// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Linux power state monitoring implementation
//!
//! Uses systemd-logind inhibitor mechanism to monitor system power events.
//! This implementation uses the `systemd-inhibit` command to take an inhibitor
//! lock and detect when the system is about to suspend/hibernate/shutdown.

use super::{PowerCallback, PowerEvent, Result};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

/// Linux power monitor using systemd-logind
pub struct LinuxPowerMonitor {
    callbacks: Arc<Mutex<Vec<PowerCallback>>>,
    running: Arc<AtomicBool>,
    monitor_thread: Option<thread::JoinHandle<()>>,
    inhibitor_process: Arc<Mutex<Option<Child>>>,
}

impl LinuxPowerMonitor {
    pub fn new() -> Self {
        Self {
            callbacks: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            monitor_thread: None,
            inhibitor_process: Arc::new(Mutex::new(None)),
        }
    }

    pub fn register_callback(&mut self, callback: PowerCallback) {
        self.callbacks.lock().unwrap().push(callback);
    }

    pub fn start(&mut self) -> Result<()> {
        let running = self.running.load(Ordering::SeqCst);
        if running {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);

        let callbacks = self.callbacks.clone();
        let running_flag = self.running.clone();
        let inhibitor_process = self.inhibitor_process.clone();

        let handle = thread::spawn(move || {
            // Try to use systemd-inhibit for power monitoring
            // This creates an inhibitor lock that we can detect when it's about to be overridden

            // First, check if systemd is available
            if !is_systemd_available() {
                eprintln!("systemd not available, using polling-based power monitoring");
                run_polling_monitor(callbacks, running_flag);
                return;
            }

            // Start the inhibitor-based monitoring
            run_inhibitor_monitor(callbacks, running_flag, inhibitor_process);
        });

        self.monitor_thread = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(false, Ordering::SeqCst);

        // Kill any running inhibitor process
        if let Ok(mut guard) = self.inhibitor_process.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
            *guard = None;
        }

        // Wait for monitor thread to finish
        if let Some(handle) = self.monitor_thread.take() {
            let _ = handle.join();
        }

        Ok(())
    }

    /// Triggers callbacks for a power event (for testing)
    #[allow(dead_code)]
    pub(crate) fn trigger_event(&self, event: PowerEvent) {
        let callbacks = self.callbacks.lock().unwrap();
        for callback in callbacks.iter() {
            callback(event);
        }
    }
}

impl Default for LinuxPowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LinuxPowerMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Check if systemd is available on this system
fn is_systemd_available() -> bool {
    Command::new("systemctl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Monitor power state using systemd-inhibit
///
/// This works by creating an inhibitor lock and then monitoring for
/// PrepareForSleep/PrepareForShutdown signals via loginctl.
fn run_inhibitor_monitor(
    callbacks: Arc<Mutex<Vec<PowerCallback>>>,
    running: Arc<AtomicBool>,
    inhibitor_process: Arc<Mutex<Option<Child>>>,
) {
    // Use gdbus or busctl to monitor logind signals
    // busctl monitor org.freedesktop.login1 is more reliable
    let mut monitor_cmd = if Command::new("busctl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        // Use busctl to monitor D-Bus signals
        let mut cmd = Command::new("busctl");
        cmd.args([
            "monitor",
            "--system",
            "--match", "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
            "--match", "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForShutdown'",
        ]);
        cmd
    } else if Command::new("gdbus")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        // Fall back to gdbus
        let mut cmd = Command::new("gdbus");
        cmd.args([
            "monitor",
            "--system",
            "--dest",
            "org.freedesktop.login1",
            "--object-path",
            "/org/freedesktop/login1",
        ]);
        cmd
    } else {
        // No D-Bus tools available, fall back to polling
        run_polling_monitor(callbacks, running);
        return;
    };

    let child = monitor_cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start D-Bus monitor: {}", e);
            run_polling_monitor(callbacks, running);
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            eprintln!("Failed to capture D-Bus monitor output");
            let _ = child.kill();
            run_polling_monitor(callbacks, running);
            return;
        }
    };

    // Store the child process for cleanup by stop()
    // This allows external termination when blocking on readline
    *inhibitor_process.lock().unwrap() = Some(child);

    let reader = BufReader::new(stdout);

    for line in reader.lines() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Parse D-Bus signals
        // busctl format: "‣ Type=signal ... Member=PrepareForSleep"
        // gdbus format: "... PrepareForSleep (true)"

        let event = if line.contains("PrepareForSleep") {
            if line.contains("true") || line.contains("b true") {
                Some(PowerEvent::Suspend)
            } else if line.contains("false") || line.contains("b false") {
                Some(PowerEvent::Resume)
            } else {
                None
            }
        } else if line.contains("PrepareForShutdown") {
            if line.contains("true") || line.contains("b true") {
                Some(PowerEvent::Shutdown)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(pe) = event {
            if let Ok(cbs) = callbacks.lock() {
                for callback in cbs.iter() {
                    callback(pe);
                }
            }
        }
    }

    // Clean up the child process if it wasn't killed by stop()
    if let Ok(mut guard) = inhibitor_process.lock() {
        if let Some(ref mut child) = *guard {
            let _ = child.kill();
            let _ = child.wait();
        }
        *guard = None;
    }
}

/// Fallback polling-based monitor for systems without D-Bus tools
///
/// Monitors /sys/power/state and other power-related files
fn run_polling_monitor(callbacks: Arc<Mutex<Vec<PowerCallback>>>, running: Arc<AtomicBool>) {
    let mut last_state = read_power_state();

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));

        let current_state = read_power_state();

        // Detect state changes
        if current_state != last_state {
            let event = match current_state.as_deref() {
                Some("mem") | Some("standby") | Some("freeze") => Some(PowerEvent::Suspend),
                Some("disk") => Some(PowerEvent::Hibernate),
                _ => None,
            };

            if let Some(pe) = event {
                if let Ok(cbs) = callbacks.lock() {
                    for callback in cbs.iter() {
                        callback(pe);
                    }
                }
            }

            last_state = current_state;
        }
    }
}

/// Read current power state from /sys/power/state
fn read_power_state() -> Option<String> {
    std::fs::read_to_string("/sys/power/state")
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_power_monitor_creation() {
        let monitor = LinuxPowerMonitor::new();
        assert!(!monitor.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_callback_registration() {
        let mut monitor = LinuxPowerMonitor::new();

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        monitor.register_callback(Box::new(move |_event| {
            called_clone.store(true, Ordering::SeqCst);
        }));

        assert_eq!(monitor.callbacks.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_trigger_event() {
        let mut monitor = LinuxPowerMonitor::new();

        let received_event = Arc::new(Mutex::new(None));
        let received_clone = received_event.clone();

        monitor.register_callback(Box::new(move |event| {
            *received_clone.lock().unwrap() = Some(event);
        }));

        monitor.trigger_event(PowerEvent::Suspend);

        assert_eq!(*received_event.lock().unwrap(), Some(PowerEvent::Suspend));
    }

    #[test]
    fn test_is_systemd_detection() {
        // This test just ensures the function doesn't panic
        let _ = is_systemd_available();
    }

    #[test]
    fn test_read_power_state() {
        // This test just ensures the function doesn't panic
        let _ = read_power_state();
    }
}
