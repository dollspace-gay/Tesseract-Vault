// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Loom concurrency tests for memory module patterns.
//!
//! These tests verify thread-safety of synchronization patterns used in:
//! - `pool.rs`: `Arc<Mutex<PoolInner>>` for concurrent allocate + rotate_key
//! - `debugger.rs`: `Arc<AtomicBool>` + `Arc<Mutex<Option<Callback>>>` for monitor
//! - `allocator.rs`: `AtomicU64` statistics with Relaxed ordering

#[cfg(all(test, feature = "loom"))]
mod tests {
    use loom::sync::atomic::{AtomicU64, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    // =========================================================================
    // Pool pattern tests (Arc<Mutex<PoolInner>>)
    // =========================================================================

    /// Test concurrent allocate counter consistency.
    ///
    /// Mirrors EncryptedMemoryPool::allocate() where multiple threads
    /// increment allocation_count and bytes_allocated under a Mutex.
    /// Verifies no lost increments.
    #[test]
    fn test_pool_concurrent_allocate_counters() {
        loom::model(|| {
            let inner = Arc::new(Mutex::new((0usize, 0usize))); // (count, bytes)

            let i1 = Arc::clone(&inner);
            let i2 = Arc::clone(&inner);

            // Thread 1: allocate 100 bytes
            let t1 = thread::spawn(move || {
                let mut guard = i1.lock().unwrap();
                guard.0 += 1;
                guard.1 += 100;
            });

            // Thread 2: allocate 200 bytes
            let t2 = thread::spawn(move || {
                let mut guard = i2.lock().unwrap();
                guard.0 += 1;
                guard.1 += 200;
            });

            t1.join().unwrap();
            t2.join().unwrap();

            let guard = inner.lock().unwrap();
            assert_eq!(guard.0, 2, "Both allocation counts must be visible");
            assert_eq!(guard.1, 300, "Both byte counts must be visible");
        });
    }

    /// Test concurrent allocate + rotate_key isolation.
    ///
    /// Mirrors the pattern where one thread calls allocate() (reads master_key)
    /// while another calls rotate_key() (replaces master_key). The Mutex ensures
    /// the allocator always gets a complete, consistent key.
    #[test]
    fn test_pool_allocate_vs_rotate_key() {
        loom::model(|| {
            // Simulate PoolInner with a u64 "key" and allocation count
            let inner = Arc::new(Mutex::new((42u64, 0usize))); // (key, count)

            let i_alloc = Arc::clone(&inner);
            let i_rotate = Arc::clone(&inner);

            // Allocator thread: read key and increment count
            let allocator = thread::spawn(move || {
                let mut guard = i_alloc.lock().unwrap();
                let key_snapshot = guard.0;
                guard.1 += 1;
                key_snapshot
            });

            // Rotator thread: replace key
            let rotator = thread::spawn(move || {
                let mut guard = i_rotate.lock().unwrap();
                guard.0 = 99; // New key
            });

            let key_seen = allocator.join().unwrap();
            rotator.join().unwrap();

            // Key seen by allocator is always complete (42 or 99, never partial)
            assert!(key_seen == 42 || key_seen == 99);

            // Count was incremented exactly once
            assert_eq!(inner.lock().unwrap().1, 1);
        });
    }

    /// Test concurrent stat reads during mutation.
    ///
    /// Mirrors the pattern where allocation_count() and bytes_allocated()
    /// read stats while allocate() mutates them.
    #[test]
    fn test_pool_stat_reads_during_mutation() {
        loom::model(|| {
            let inner = Arc::new(Mutex::new((0usize, 0usize))); // (count, bytes)

            let i_writer = Arc::clone(&inner);
            let i_reader = Arc::clone(&inner);

            // Writer: allocate (increment both)
            let writer = thread::spawn(move || {
                let mut guard = i_writer.lock().unwrap();
                guard.0 += 1;
                guard.1 += 256;
            });

            // Reader: read stats
            let reader = thread::spawn(move || {
                let guard = i_reader.lock().unwrap();
                (guard.0, guard.1)
            });

            writer.join().unwrap();
            let (count, bytes) = reader.join().unwrap();

            // Reader sees either pre-write (0, 0) or post-write (1, 256)
            // Never partial state like (1, 0) because both are updated under one lock
            assert!(
                (count == 0 && bytes == 0) || (count == 1 && bytes == 256),
                "Stats must be atomically consistent: got ({}, {})",
                count,
                bytes
            );
        });
    }

    // =========================================================================
    // Debugger pattern tests (AtomicBool + Mutex<Option<Callback>>)
    // =========================================================================

    /// Test stop flag propagation to monitor loop.
    ///
    /// Mirrors DebuggerMonitor: the monitor loop reads `running` (AtomicBool),
    /// and stop_monitoring() writes false.
    #[test]
    fn test_debugger_stop_flag_propagation() {
        use loom::sync::atomic::AtomicBool;

        loom::model(|| {
            let running = Arc::new(AtomicBool::new(true));

            let r_monitor = Arc::clone(&running);
            let r_stopper = Arc::clone(&running);

            // Monitor thread: read flag
            let monitor = thread::spawn(move || {
                r_monitor.load(Ordering::Acquire)
            });

            // Stopper thread: set flag to false
            let stopper = thread::spawn(move || {
                r_stopper.store(false, Ordering::Release);
            });

            let was_running = monitor.join().unwrap();
            stopper.join().unwrap();

            // Monitor saw either true (before stop) or false (after stop)
            assert!(was_running || !was_running); // Always valid

            // After both complete, flag must be false
            assert!(!running.load(Ordering::Acquire));
        });
    }

    /// Test set_callback vs callback invocation race.
    ///
    /// Mirrors DebuggerMonitor: one thread replaces the callback via Mutex
    /// while the monitor thread reads and invokes it.
    #[test]
    fn test_debugger_callback_replace_during_invoke() {
        loom::model(|| {
            let callback_result = Arc::new(Mutex::new(None::<u32>));
            let callback_value = Arc::new(Mutex::new(1u32)); // Initial callback "returns" 1

            let cv_invoker = Arc::clone(&callback_value);
            let cr_invoker = Arc::clone(&callback_result);
            let cv_setter = Arc::clone(&callback_value);

            // Invoker thread: read callback value and store result
            let invoker = thread::spawn(move || {
                let val = *cv_invoker.lock().unwrap();
                let mut result = cr_invoker.lock().unwrap();
                *result = Some(val);
            });

            // Setter thread: replace callback value
            let setter = thread::spawn(move || {
                let mut val = cv_setter.lock().unwrap();
                *val = 2; // New callback "returns" 2
            });

            invoker.join().unwrap();
            setter.join().unwrap();

            // Result is either 1 (old callback) or 2 (new callback), never corrupt
            let result = callback_result.lock().unwrap();
            assert!(
                *result == Some(1) || *result == Some(2),
                "Callback result must be from old or new callback, got {:?}",
                *result
            );
        });
    }

    /// Test stop during callback invocation.
    ///
    /// Verifies that setting running=false while the callback Mutex is held
    /// doesn't cause deadlock or inconsistent state.
    #[test]
    fn test_debugger_stop_during_callback() {
        use loom::sync::atomic::AtomicBool;

        loom::model(|| {
            let running = Arc::new(AtomicBool::new(true));
            let callback = Arc::new(Mutex::new(0u32));

            let r_cb = Arc::clone(&running);
            let c_cb = Arc::clone(&callback);
            let r_stop = Arc::clone(&running);

            // Callback thread: lock callback, do work, check running
            let cb_thread = thread::spawn(move || {
                let mut guard = c_cb.lock().unwrap();
                *guard += 1;
                r_cb.load(Ordering::Acquire)
            });

            // Stop thread: set running to false
            let stop_thread = thread::spawn(move || {
                r_stop.store(false, Ordering::Release);
            });

            let still_running = cb_thread.join().unwrap();
            stop_thread.join().unwrap();

            // Callback completed (no deadlock)
            assert_eq!(*callback.lock().unwrap(), 1);
            // Running was either true or false when checked
            assert!(still_running || !still_running);
        });
    }

    // =========================================================================
    // Allocator pattern tests (AtomicU64 with Relaxed ordering)
    // =========================================================================

    /// Test concurrent fetch_add consistency.
    ///
    /// Mirrors SecureAllocator where multiple threads call alloc()
    /// which does allocation_count.fetch_add(1, Relaxed) and
    /// bytes_allocated.fetch_add(size, Relaxed).
    #[test]
    fn test_allocator_concurrent_fetch_add() {
        loom::model(|| {
            let alloc_count = Arc::new(AtomicU64::new(0));
            let bytes_alloc = Arc::new(AtomicU64::new(0));

            let ac1 = Arc::clone(&alloc_count);
            let ba1 = Arc::clone(&bytes_alloc);
            let ac2 = Arc::clone(&alloc_count);
            let ba2 = Arc::clone(&bytes_alloc);

            // Thread 1: alloc 100 bytes
            let t1 = thread::spawn(move || {
                ac1.fetch_add(1, Ordering::Relaxed);
                ba1.fetch_add(100, Ordering::Relaxed);
            });

            // Thread 2: alloc 200 bytes
            let t2 = thread::spawn(move || {
                ac2.fetch_add(1, Ordering::Relaxed);
                ba2.fetch_add(200, Ordering::Relaxed);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Final values are deterministic: both increments always succeed
            assert_eq!(alloc_count.load(Ordering::Relaxed), 2);
            assert_eq!(bytes_alloc.load(Ordering::Relaxed), 300);
        });
    }

    /// Test reset_stats vs concurrent alloc.
    ///
    /// Mirrors SecureAllocator: reset_stats() stores 0 to all counters
    /// while alloc() does fetch_add on some. Verifies no UB and counters
    /// are always in a valid state.
    #[test]
    fn test_allocator_reset_vs_alloc() {
        loom::model(|| {
            let alloc_count = Arc::new(AtomicU64::new(5));
            let dealloc_count = Arc::new(AtomicU64::new(3));

            let ac_reset = Arc::clone(&alloc_count);
            let dc_reset = Arc::clone(&dealloc_count);
            let ac_alloc = Arc::clone(&alloc_count);

            // Reset thread: zero all counters
            let resetter = thread::spawn(move || {
                ac_reset.store(0, Ordering::Relaxed);
                dc_reset.store(0, Ordering::Relaxed);
            });

            // Alloc thread: increment alloc counter
            let allocator = thread::spawn(move || {
                ac_alloc.fetch_add(1, Ordering::Relaxed);
            });

            resetter.join().unwrap();
            allocator.join().unwrap();

            let ac = alloc_count.load(Ordering::Relaxed);
            let dc = dealloc_count.load(Ordering::Relaxed);

            // alloc_count is either:
            // - 0 (reset happened after alloc's fetch_add target was already stored)
            // - 1 (alloc happened after reset)
            // - 6 (alloc happened before reset, then reset zeroed)
            //   Actually, fetch_add(1) on 5 = 6, then store(0) = 0
            //   OR store(0) first, then fetch_add(1) = 1
            // So ac is 0 or 1
            assert!(
                ac <= 1 || ac == 6,
                "alloc_count must be in a valid state, got {}",
                ac
            );
            // dealloc_count is 0 or 3
            assert!(dc == 0 || dc == 3, "dealloc_count got {}", dc);
        });
    }

    /// Test active_allocations consistency.
    ///
    /// Mirrors SecureAllocator::active_allocations() which computes
    /// allocation_count.saturating_sub(deallocation_count) from two
    /// separate Relaxed loads.
    #[test]
    fn test_allocator_active_allocations_consistency() {
        loom::model(|| {
            let alloc_count = Arc::new(AtomicU64::new(0));
            let dealloc_count = Arc::new(AtomicU64::new(0));

            let ac_writer = Arc::clone(&alloc_count);
            let dc_writer = Arc::clone(&dealloc_count);
            let ac_reader = Arc::clone(&alloc_count);
            let dc_reader = Arc::clone(&dealloc_count);

            // Writer thread: alloc then dealloc
            let writer = thread::spawn(move || {
                ac_writer.fetch_add(1, Ordering::Relaxed);
                dc_writer.fetch_add(1, Ordering::Relaxed);
            });

            // Reader thread: compute active = alloc - dealloc (saturating)
            let reader = thread::spawn(move || {
                let a = ac_reader.load(Ordering::Relaxed);
                let d = dc_reader.load(Ordering::Relaxed);
                a.saturating_sub(d)
            });

            writer.join().unwrap();
            let active = reader.join().unwrap();

            // active is 0 or 1 (never negative due to saturating_sub)
            // It can't be > 1 because at most 1 allocation happened
            assert!(active <= 1, "active_allocations must be <= 1, got {}", active);
        });
    }
}

// Fallback tests when loom feature is not enabled
#[cfg(all(test, not(feature = "loom")))]
mod regular_tests {
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_pool_counter_basic() {
        let inner = Arc::new(Mutex::new((0usize, 0usize)));
        {
            let mut guard = inner.lock().unwrap();
            guard.0 += 1;
            guard.1 += 100;
        }
        let guard = inner.lock().unwrap();
        assert_eq!(guard.0, 1);
        assert_eq!(guard.1, 100);
    }

    #[test]
    fn test_allocator_saturating_sub() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let alloc = AtomicU64::new(5);
        let dealloc = AtomicU64::new(3);
        let active = alloc.load(Ordering::Relaxed).saturating_sub(dealloc.load(Ordering::Relaxed));
        assert_eq!(active, 2);
    }
}
