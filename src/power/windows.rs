// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Windows power state monitoring implementation
//!
//! Uses Windows Power Management API to monitor system power events
//! like suspend, hibernate, and shutdown through WM_POWERBROADCAST messages.

use super::{PowerCallback, PowerEvent, Result};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;

use winapi::shared::minwindef::{LPARAM, LRESULT, UINT, WPARAM};
use winapi::shared::windef::HWND;
use winapi::um::winuser::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    PostMessageW, RegisterClassW, TranslateMessage, CS_HREDRAW, CS_VREDRAW,
    HWND_MESSAGE, MSG, WM_DESTROY, WM_POWERBROADCAST, WM_QUIT, WM_USER,
    WNDCLASSW,
};

// Power broadcast constants
const PBT_APMSUSPEND: WPARAM = 0x0004;
const PBT_APMRESUMESUSPEND: WPARAM = 0x0007;
const PBT_APMRESUMEAUTOMATIC: WPARAM = 0x0012;
const PBT_APMPOWERSTATUSCHANGE: WPARAM = 0x000A;

/// Custom message to stop the message loop
const WM_STOP_MONITORING: UINT = WM_USER + 1;

/// Wrapper for HWND that is Send + Sync (Windows HWNDs are safe to share across threads)
#[derive(Clone, Copy)]
struct SendableHwnd(HWND);

// SAFETY: Windows HWNDs are thread-safe handles that can be passed between threads
unsafe impl Send for SendableHwnd {}
unsafe impl Sync for SendableHwnd {}

/// Shared state for the window procedure
struct WindowState {
    callbacks: Arc<Mutex<Vec<PowerCallback>>>,
}

/// Global storage for window state (needed for window procedure)
static WINDOW_STATE: std::sync::OnceLock<Mutex<Option<Arc<WindowState>>>> = std::sync::OnceLock::new();

fn get_window_state_storage() -> &'static Mutex<Option<Arc<WindowState>>> {
    WINDOW_STATE.get_or_init(|| Mutex::new(None))
}

/// Windows power monitor using message-only window
pub struct WindowsPowerMonitor {
    callbacks: Arc<Mutex<Vec<PowerCallback>>>,
    running: Arc<AtomicBool>,
    monitor_thread: Option<thread::JoinHandle<()>>,
    window_handle: Arc<Mutex<Option<SendableHwnd>>>,
}

impl WindowsPowerMonitor {
    pub fn new() -> Self {
        Self {
            callbacks: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            monitor_thread: None,
            window_handle: Arc::new(Mutex::new(None)),
        }
    }

    pub fn register_callback(&mut self, callback: PowerCallback) {
        self.callbacks.lock().unwrap().push(callback);
    }

    pub fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);

        // Set up global state for window procedure
        let state = Arc::new(WindowState {
            callbacks: self.callbacks.clone(),
        });
        *get_window_state_storage().lock().unwrap() = Some(state);

        let running = self.running.clone();
        let window_handle = self.window_handle.clone();

        let handle = thread::spawn(move || {
            unsafe {
                // Register window class
                let class_name: Vec<u16> = "TesseractPowerMonitor\0"
                    .encode_utf16()
                    .collect();

                let wc = WNDCLASSW {
                    style: CS_HREDRAW | CS_VREDRAW,
                    lpfnWndProc: Some(power_window_proc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: std::ptr::null_mut(),
                    hIcon: std::ptr::null_mut(),
                    hCursor: std::ptr::null_mut(),
                    hbrBackground: std::ptr::null_mut(),
                    lpszMenuName: std::ptr::null(),
                    lpszClassName: class_name.as_ptr(),
                };

                let atom = RegisterClassW(&wc);
                if atom == 0 {
                    eprintln!("Failed to register window class for power monitoring");
                    running.store(false, Ordering::SeqCst);
                    return;
                }

                // Create message-only window
                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    std::ptr::null(),
                    0,
                    0, 0, 0, 0,
                    HWND_MESSAGE,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );

                if hwnd.is_null() {
                    eprintln!("Failed to create message-only window for power monitoring");
                    running.store(false, Ordering::SeqCst);
                    return;
                }

                // Store window handle for stop() to use
                *window_handle.lock().unwrap() = Some(SendableHwnd(hwnd));

                // Message loop
                let mut msg: MSG = std::mem::zeroed();
                while running.load(Ordering::SeqCst) {
                    let result = GetMessageW(&mut msg, hwnd, 0, 0);

                    if result == 0 || result == -1 {
                        break;
                    }

                    if msg.message == WM_STOP_MONITORING {
                        break;
                    }

                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }

                // Cleanup
                DestroyWindow(hwnd);
                *window_handle.lock().unwrap() = None;

                // Clear global state
                *get_window_state_storage().lock().unwrap() = None;
            }
        });

        self.monitor_thread = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(false, Ordering::SeqCst);

        // Send stop message to break the message loop
        if let Some(hwnd) = *self.window_handle.lock().unwrap() {
            unsafe {
                PostMessageW(hwnd.0, WM_STOP_MONITORING, 0, 0);
            }
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

impl Default for WindowsPowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WindowsPowerMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Window procedure for handling power broadcast messages
unsafe extern "system" fn power_window_proc(
    hwnd: HWND,
    msg: UINT,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_POWERBROADCAST => {
            let power_event = match wparam {
                PBT_APMSUSPEND => Some(PowerEvent::Suspend),
                PBT_APMRESUMESUSPEND | PBT_APMRESUMEAUTOMATIC => Some(PowerEvent::Resume),
                PBT_APMPOWERSTATUSCHANGE => {
                    // Power status changed - could be battery/AC transition
                    // We don't trigger callbacks for this by default
                    None
                }
                _ => None,
            };

            if let Some(event) = power_event {
                if let Some(state) = get_window_state_storage().lock().ok().and_then(|g| g.clone()) {
                    if let Ok(callbacks) = state.callbacks.lock() {
                        for callback in callbacks.iter() {
                            callback(event);
                        }
                    }
                }
            }

            1 // TRUE - allow the operation
        }
        WM_DESTROY => {
            PostMessageW(hwnd, WM_QUIT, 0, 0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_power_monitor_creation() {
        let monitor = WindowsPowerMonitor::new();
        assert!(!monitor.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_callback_registration() {
        let mut monitor = WindowsPowerMonitor::new();

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        monitor.register_callback(Box::new(move |_event| {
            called_clone.store(true, Ordering::SeqCst);
        }));

        assert_eq!(monitor.callbacks.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_trigger_event() {
        let mut monitor = WindowsPowerMonitor::new();

        let received_event = Arc::new(Mutex::new(None));
        let received_clone = received_event.clone();

        monitor.register_callback(Box::new(move |event| {
            *received_clone.lock().unwrap() = Some(event);
        }));

        monitor.trigger_event(PowerEvent::Suspend);

        assert_eq!(*received_event.lock().unwrap(), Some(PowerEvent::Suspend));
    }

    #[test]
    fn test_start_stop() {
        let mut monitor = WindowsPowerMonitor::new();

        // Start should succeed
        assert!(monitor.start().is_ok());
        assert!(monitor.running.load(Ordering::SeqCst));

        // Starting again should be no-op
        assert!(monitor.start().is_ok());

        // Give the thread time to start
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Stop should succeed
        assert!(monitor.stop().is_ok());
        assert!(!monitor.running.load(Ordering::SeqCst));

        // Stopping again should be no-op
        assert!(monitor.stop().is_ok());
    }
}
