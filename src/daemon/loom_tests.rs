// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Loom concurrency tests for daemon server patterns.
//!
//! Loom is a tool for testing concurrent Rust code by exhaustively
//! exploring all possible thread interleavings. These tests verify
//! that our synchronization patterns are correct.
//!
//! Note: Loom tests are only run when the `loom` feature is enabled.

#[cfg(all(test, feature = "loom"))]
mod tests {
    use loom::sync::atomic::{AtomicBool, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    /// Test that shutdown flag is correctly propagated across threads.
    ///
    /// This mirrors the shutdown pattern in DaemonServer where:
    /// 1. Main thread checks shutdown_flag in a loop
    /// 2. Signal handler or external code sets shutdown_flag
    /// 3. Main thread observes the flag and exits
    #[test]
    fn test_shutdown_flag_propagation() {
        loom::model(|| {
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let flag_clone = Arc::clone(&shutdown_flag);

            // Spawn a thread that signals shutdown
            let signaler = thread::spawn(move || {
                flag_clone.store(true, Ordering::Release);
            });

            // Main loop checking for shutdown
            // In real code this would be in a loop, but for Loom we just check once
            let observed = shutdown_flag.load(Ordering::Acquire);

            signaler.join().unwrap();

            // After join, the flag must be true
            assert!(shutdown_flag.load(Ordering::Acquire));

            // The observed value could be either true or false depending on
            // thread interleaving (before or after the store)
            let _ = observed;
        });
    }

    /// Test concurrent access to shared mount state.
    ///
    /// This mirrors the pattern where multiple client handlers may
    /// access the mounts HashMap concurrently through a Mutex.
    #[test]
    fn test_concurrent_mount_access() {
        loom::model(|| {
            let mounts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

            let mounts1 = Arc::clone(&mounts);
            let mounts2 = Arc::clone(&mounts);

            // Thread 1: Add a mount
            let t1 = thread::spawn(move || {
                let mut guard = mounts1.lock().unwrap();
                guard.push("mount1".to_string());
            });

            // Thread 2: Add another mount
            let t2 = thread::spawn(move || {
                let mut guard = mounts2.lock().unwrap();
                guard.push("mount2".to_string());
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Both mounts should be present
            let guard = mounts.lock().unwrap();
            assert_eq!(guard.len(), 2);
            assert!(guard.contains(&"mount1".to_string()));
            assert!(guard.contains(&"mount2".to_string()));
        });
    }

    /// Test that shutdown flag prevents new work from starting.
    ///
    /// This verifies the pattern where we check shutdown before
    /// accepting new connections.
    #[test]
    fn test_shutdown_prevents_new_work() {
        loom::model(|| {
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let work_started = Arc::new(AtomicBool::new(false));

            let flag_clone = Arc::clone(&shutdown_flag);
            let work_clone = Arc::clone(&work_started);

            // Worker thread: only start work if not shutting down
            let worker = thread::spawn(move || {
                if !flag_clone.load(Ordering::Acquire) {
                    work_clone.store(true, Ordering::Release);
                }
            });

            // Signal thread: trigger shutdown
            let flag_clone2 = Arc::clone(&shutdown_flag);
            let signaler = thread::spawn(move || {
                flag_clone2.store(true, Ordering::Release);
            });

            worker.join().unwrap();
            signaler.join().unwrap();

            // Either work started (worker ran first) or it didn't (signaler ran first)
            // Both are valid outcomes - we just verify no crash/deadlock
            let _ = work_started.load(Ordering::Acquire);
        });
    }

    /// Test mutex lock/unlock ordering with shutdown.
    ///
    /// Verifies that we properly release locks before shutdown cleanup.
    #[test]
    fn test_mutex_release_before_shutdown() {
        loom::model(|| {
            let state = Arc::new(Mutex::new(0u32));
            let shutdown = Arc::new(AtomicBool::new(false));

            let state1 = Arc::clone(&state);
            let shutdown1 = Arc::clone(&shutdown);

            // Thread that holds lock and updates state
            let updater = thread::spawn(move || {
                let mut guard = state1.lock().unwrap();
                *guard += 1;
                drop(guard); // Explicitly release lock

                // Check if we should continue
                !shutdown1.load(Ordering::Acquire)
            });

            // Thread that signals shutdown
            let shutdown2 = Arc::clone(&shutdown);
            let signaler = thread::spawn(move || {
                shutdown2.store(true, Ordering::Release);
            });

            let _should_continue = updater.join().unwrap();
            signaler.join().unwrap();

            // State should have been updated
            let guard = state.lock().unwrap();
            assert_eq!(*guard, 1);
        });
    }

    /// Test double-check pattern for mount existence.
    ///
    /// In the daemon, we check if a volume is mounted before mounting.
    /// This tests that pattern doesn't have TOCTOU issues with Mutex.
    #[test]
    fn test_mount_check_then_insert() {
        loom::model(|| {
            let mounts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

            let mounts1 = Arc::clone(&mounts);
            let mounts2 = Arc::clone(&mounts);

            let t1 = thread::spawn(move || {
                let mut guard = mounts1.lock().unwrap();
                if !guard.contains(&"volume1".to_string()) {
                    guard.push("volume1".to_string());
                    true // mounted successfully
                } else {
                    false // already mounted
                }
            });

            let t2 = thread::spawn(move || {
                let mut guard = mounts2.lock().unwrap();
                if !guard.contains(&"volume1".to_string()) {
                    guard.push("volume1".to_string());
                    true // mounted successfully
                } else {
                    false // already mounted
                }
            });

            let result1 = t1.join().unwrap();
            let result2 = t2.join().unwrap();

            // Exactly one should succeed
            assert!(result1 ^ result2);

            // Volume should appear exactly once
            let guard = mounts.lock().unwrap();
            assert_eq!(guard.iter().filter(|&s| s == "volume1").count(), 1);
        });
    }
}

// Placeholder tests for when loom feature is not enabled
#[cfg(all(test, not(feature = "loom")))]
mod regular_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_shutdown_flag_basic() {
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.load(Ordering::Relaxed));

        flag.store(true, Ordering::Relaxed);
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn test_mutex_basic() {
        let data = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut guard = data.lock().unwrap();
        guard.push("test".to_string());
        assert_eq!(guard.len(), 1);
    }
}
