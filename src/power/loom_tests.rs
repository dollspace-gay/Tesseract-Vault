// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Loom concurrency tests for power monitoring patterns.
//!
//! These tests verify the thread-safety of synchronization patterns used
//! in WindowsPowerMonitor and LinuxPowerMonitor:
//! - `Arc<Mutex<Vec<Callback>>>` for callback registration/invocation
//! - `Arc<AtomicBool>` for running flag coordination
//! - Start/stop lifecycle with thread shutdown

#[cfg(all(test, feature = "loom"))]
mod tests {
    use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    /// Test concurrent callback registration while callbacks are being invoked.
    ///
    /// This mirrors the power monitor pattern where register_callback() takes
    /// &mut self but trigger_event() takes &self — both access Arc<Mutex<Vec<Callback>>>.
    /// Verifies that Mutex prevents data races on the callback vector.
    #[test]
    fn test_concurrent_callback_registration_and_invocation() {
        loom::model(|| {
            let callbacks: Arc<Mutex<Vec<Box<dyn Fn() + Send + Sync>>>> =
                Arc::new(Mutex::new(Vec::new()));
            let call_count = Arc::new(AtomicUsize::new(0));

            let callbacks1 = Arc::clone(&callbacks);
            let count1 = Arc::clone(&call_count);

            // Thread 1: Register a callback
            let registrar = thread::spawn(move || {
                let mut guard = callbacks1.lock().unwrap();
                guard.push(Box::new(move || {
                    count1.fetch_add(1, Ordering::SeqCst);
                }));
            });

            let callbacks2 = Arc::clone(&callbacks);

            // Thread 2: Invoke all registered callbacks (may be empty or have one)
            let invoker = thread::spawn(move || {
                let guard = callbacks2.lock().unwrap();
                for cb in guard.iter() {
                    cb();
                }
                guard.len()
            });

            registrar.join().unwrap();
            let invoked_count = invoker.join().unwrap();

            // After both threads complete, exactly 1 callback registered
            let guard = callbacks.lock().unwrap();
            assert_eq!(guard.len(), 1);

            // Invocation saw either 0 or 1 callbacks depending on ordering
            assert!(invoked_count <= 1);
        });
    }

    /// Test start/stop flag coordination between monitor and signal threads.
    ///
    /// Mirrors the pattern in WindowsPowerMonitor::start()/stop() where:
    /// - start() sets running=true, spawns monitor thread
    /// - stop() sets running=false, monitor thread observes and exits
    /// - Double-start is a no-op (check before store)
    #[test]
    fn test_start_stop_flag_coordination() {
        loom::model(|| {
            let running = Arc::new(AtomicBool::new(false));

            let running1 = Arc::clone(&running);

            // "start" — only start if not already running
            let starter = thread::spawn(move || {
                if !running1.load(Ordering::SeqCst) {
                    running1.store(true, Ordering::SeqCst);
                    true // started
                } else {
                    false // already running
                }
            });

            let running2 = Arc::clone(&running);

            // "stop" — only stop if currently running
            let stopper = thread::spawn(move || {
                if running2.load(Ordering::SeqCst) {
                    running2.store(false, Ordering::SeqCst);
                    true // stopped
                } else {
                    false // wasn't running
                }
            });

            let did_start = starter.join().unwrap();
            let did_stop = stopper.join().unwrap();

            // If start ran before stop: started=true, stop saw it running
            // If stop ran before start: stop saw not-running, start then ran
            // Both are valid — no crash/deadlock is the key property
            let _ = (did_start, did_stop);
        });
    }

    /// Test that the running flag is correctly observed by a polling loop.
    ///
    /// Mirrors the monitor thread pattern: the monitor thread polls running
    /// in a loop, and stop() sets it to false to break the loop.
    #[test]
    fn test_monitor_thread_shutdown() {
        loom::model(|| {
            let running = Arc::new(AtomicBool::new(true));
            let iterations = Arc::new(AtomicUsize::new(0));

            let running_clone = Arc::clone(&running);
            let iter_clone = Arc::clone(&iterations);

            // Monitor thread: loop while running, counting iterations
            let monitor = thread::spawn(move || {
                while running_clone.load(Ordering::SeqCst) {
                    iter_clone.fetch_add(1, Ordering::Relaxed);
                    // In real code this would block on GetMessage/select/poll,
                    // but for Loom we just do one iteration check
                    break; // Loom can't handle unbounded loops
                }
            });

            let running_stop = Arc::clone(&running);

            // Signal thread: tell monitor to stop
            let signaler = thread::spawn(move || {
                running_stop.store(false, Ordering::SeqCst);
            });

            monitor.join().unwrap();
            signaler.join().unwrap();

            // Monitor ran at most 1 iteration, no deadlock
            assert!(iterations.load(Ordering::Relaxed) <= 1);
        });
    }

    /// Test concurrent callback invocation from multiple event sources.
    ///
    /// Mirrors the scenario where a power event arrives while the
    /// monitor is already processing a previous event — both try to
    /// lock the callback vector.
    #[test]
    fn test_concurrent_event_dispatch() {
        loom::model(|| {
            let event_count = Arc::new(AtomicUsize::new(0));
            let callbacks: Arc<Mutex<Vec<Box<dyn Fn() + Send + Sync>>>> =
                Arc::new(Mutex::new(Vec::new()));

            // Pre-register a callback
            {
                let count = Arc::clone(&event_count);
                callbacks.lock().unwrap().push(Box::new(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                }));
            }

            let cb1 = Arc::clone(&callbacks);
            let cb2 = Arc::clone(&callbacks);

            // Two threads dispatching events concurrently
            let t1 = thread::spawn(move || {
                let guard = cb1.lock().unwrap();
                for cb in guard.iter() {
                    cb();
                }
            });

            let t2 = thread::spawn(move || {
                let guard = cb2.lock().unwrap();
                for cb in guard.iter() {
                    cb();
                }
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Both events dispatched, callback ran exactly twice
            assert_eq!(event_count.load(Ordering::SeqCst), 2);
        });
    }

    /// Test stop with concurrent callback invocation.
    ///
    /// Mirrors the race where stop() is called while trigger_event()
    /// is executing — the Mutex ensures callbacks complete before
    /// the vector is cleared/dropped.
    #[test]
    fn test_stop_during_callback_invocation() {
        loom::model(|| {
            let running = Arc::new(AtomicBool::new(true));
            let invoked = Arc::new(AtomicBool::new(false));
            let callbacks: Arc<Mutex<Vec<Box<dyn Fn() + Send + Sync>>>> =
                Arc::new(Mutex::new(Vec::new()));

            {
                let inv = Arc::clone(&invoked);
                callbacks.lock().unwrap().push(Box::new(move || {
                    inv.store(true, Ordering::SeqCst);
                }));
            }

            let running1 = Arc::clone(&running);
            let cb1 = Arc::clone(&callbacks);

            // Thread 1: dispatch event if still running
            let dispatcher = thread::spawn(move || {
                if running1.load(Ordering::SeqCst) {
                    let guard = cb1.lock().unwrap();
                    for cb in guard.iter() {
                        cb();
                    }
                }
            });

            let running2 = Arc::clone(&running);
            let cb2 = Arc::clone(&callbacks);

            // Thread 2: stop — set flag and clear callbacks
            let stopper = thread::spawn(move || {
                running2.store(false, Ordering::SeqCst);
                let mut guard = cb2.lock().unwrap();
                guard.clear();
            });

            dispatcher.join().unwrap();
            stopper.join().unwrap();

            // Callback may or may not have been invoked depending on ordering
            // Key property: no deadlock, no use-after-free
            let _ = invoked.load(Ordering::SeqCst);

            // After stop, callbacks vector is empty
            assert_eq!(callbacks.lock().unwrap().len(), 0);
        });
    }
}

// Fallback tests when loom feature is not enabled
#[cfg(all(test, not(feature = "loom")))]
mod regular_tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    type Callbacks = Arc<Mutex<Vec<Box<dyn Fn() + Send + Sync>>>>;

    #[test]
    fn test_callback_vector_thread_safety() {
        let callbacks: Callbacks = Arc::new(Mutex::new(Vec::new()));
        let count = Arc::new(AtomicUsize::new(0));

        let c = Arc::clone(&count);
        callbacks.lock().unwrap().push(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));

        let guard = callbacks.lock().unwrap();
        for cb in guard.iter() {
            cb();
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_running_flag_lifecycle() {
        let running = Arc::new(AtomicBool::new(false));

        // Start
        assert!(!running.load(Ordering::SeqCst));
        running.store(true, Ordering::SeqCst);
        assert!(running.load(Ordering::SeqCst));

        // Stop
        running.store(false, Ordering::SeqCst);
        assert!(!running.load(Ordering::SeqCst));
    }
}
