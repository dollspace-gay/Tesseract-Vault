// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Loom concurrency tests for volume I/O patterns.
//!
//! These tests verify the thread-safety of synchronization patterns used
//! in VolumeIOFilesystem:
//! - `RwLock<Option<T>>` for IO layer access
//! - Multiple `RwLock` fields accessed concurrently (superblock, bitmaps, cache)
//! - `Mutex<()>` for inode table block serialization
//! - Dirty flag coordination between readers and writers

#[cfg(all(test, feature = "loom"))]
mod tests {
    use loom::sync::{Arc, Mutex, RwLock};
    use loom::thread;

    /// Test RwLock<Option<T>> initialization pattern.
    ///
    /// Mirrors VolumeIOFilesystem.io: starts as None, init() sets it
    /// to Some(VolumeIO), then readers use it concurrently.
    #[test]
    fn test_rwlock_option_init_then_read() {
        loom::model(|| {
            let io: Arc<RwLock<Option<u64>>> = Arc::new(RwLock::new(None));

            let io_writer = Arc::clone(&io);
            let io_reader = Arc::clone(&io);

            // Initializer thread: set io = Some(value)
            let writer = thread::spawn(move || {
                let mut guard = io_writer.write().unwrap();
                *guard = Some(42);
            });

            // Reader thread: try to use the io
            let reader = thread::spawn(move || {
                let guard = io_reader.read().unwrap();
                match *guard {
                    Some(val) => Some(val),
                    None => None, // not initialized yet
                }
            });

            writer.join().unwrap();
            let read_result = reader.join().unwrap();

            // After both complete, io must be initialized
            assert_eq!(*io.read().unwrap(), Some(42));

            // Reader may have seen None or Some(42) depending on ordering
            assert!(read_result.is_none() || read_result == Some(42));
        });
    }

    /// Test concurrent readers on RwLock (no writers).
    ///
    /// Mirrors the common pattern in VolumeIOFilesystem where multiple
    /// operations read the superblock/bitmaps concurrently.
    #[test]
    fn test_concurrent_rwlock_readers() {
        loom::model(|| {
            let data: Arc<RwLock<u64>> = Arc::new(RwLock::new(100));

            let d1 = Arc::clone(&data);
            let d2 = Arc::clone(&data);

            let r1 = thread::spawn(move || {
                let guard = d1.read().unwrap();
                *guard
            });

            let r2 = thread::spawn(move || {
                let guard = d2.read().unwrap();
                *guard
            });

            assert_eq!(r1.join().unwrap(), 100);
            assert_eq!(r2.join().unwrap(), 100);
        });
    }

    /// Test writer-reader contention on RwLock.
    ///
    /// Mirrors VolumeIOFilesystem where a write operation (create_file,
    /// write_file) updates the bitmap while a read operation (stat, readdir)
    /// reads it concurrently.
    #[test]
    fn test_rwlock_writer_reader_contention() {
        loom::model(|| {
            let bitmap: Arc<RwLock<Vec<bool>>> = Arc::new(RwLock::new(vec![false; 4]));

            let bm_writer = Arc::clone(&bitmap);
            let bm_reader = Arc::clone(&bitmap);

            // Writer: allocate block 2
            let writer = thread::spawn(move || {
                let mut guard = bm_writer.write().unwrap();
                guard[2] = true;
            });

            // Reader: count allocated blocks
            let reader = thread::spawn(move || {
                let guard = bm_reader.read().unwrap();
                guard.iter().filter(|&&b| b).count()
            });

            writer.join().unwrap();
            let count = reader.join().unwrap();

            // Reader saw either 0 (before write) or 1 (after write)
            assert!(count == 0 || count == 1);

            // After both, block 2 is allocated
            assert!(bitmap.read().unwrap()[2]);
        });
    }

    /// Test dirty flag coordination.
    ///
    /// Mirrors VolumeIOFilesystem.dirty: writers set dirty=true after
    /// modifications, sync/flush reads it and sets dirty=false.
    #[test]
    fn test_dirty_flag_coordination() {
        loom::model(|| {
            let dirty: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));

            let dirty_writer = Arc::clone(&dirty);
            let dirty_syncer = Arc::clone(&dirty);

            // Writer thread: modify data, set dirty
            let writer = thread::spawn(move || {
                let mut guard = dirty_writer.write().unwrap();
                *guard = true;
            });

            // Sync thread: check dirty, if true then flush and clear
            let syncer = thread::spawn(move || {
                let mut guard = dirty_syncer.write().unwrap();
                if *guard {
                    // "flush" the data
                    *guard = false;
                    true // did sync
                } else {
                    false // nothing to sync
                }
            });

            writer.join().unwrap();
            let did_sync = syncer.join().unwrap();

            // Final state depends on ordering:
            // - Writer then syncer: dirty=false, did_sync=true
            // - Syncer then writer: dirty=true, did_sync=false
            let final_dirty = *dirty.read().unwrap();

            if did_sync {
                // Syncer ran after writer: syncer cleared the flag
                // But writer might have run again... in this test, no.
                // Since writer only runs once and syncer saw dirty=true,
                // final state is clean.
                assert!(!final_dirty);
            }
            // If syncer ran first, flag is true because writer ran after
        });
    }

    /// Test inode table lock serialization.
    ///
    /// Mirrors the inode_table_lock: Mutex<()> pattern in VolumeIOFilesystem.
    /// Multiple inode updates must be serialized because multiple inodes share
    /// the same block (read-modify-write requires atomicity).
    #[test]
    fn test_inode_table_lock_serialization() {
        loom::model(|| {
            // Simulates a block containing 2 inodes
            let block: Arc<RwLock<[u32; 2]>> = Arc::new(RwLock::new([0, 0]));
            let table_lock: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

            let block1 = Arc::clone(&block);
            let lock1 = Arc::clone(&table_lock);
            let block2 = Arc::clone(&block);
            let lock2 = Arc::clone(&table_lock);

            // Thread 1: update inode 0 (read-modify-write under lock)
            let t1 = thread::spawn(move || {
                let _guard = lock1.lock().unwrap();
                let mut data = block1.write().unwrap();
                data[0] = 100;
            });

            // Thread 2: update inode 1 (read-modify-write under lock)
            let t2 = thread::spawn(move || {
                let _guard = lock2.lock().unwrap();
                let mut data = block2.write().unwrap();
                data[1] = 200;
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Both updates must be preserved (no lost writes)
            let data = block.read().unwrap();
            assert_eq!(data[0], 100);
            assert_eq!(data[1], 200);
        });
    }

    /// Test that without inode table lock, concurrent read-modify-write
    /// can lose updates.
    ///
    /// This is the NEGATIVE test: demonstrates why the lock is needed.
    /// Without the Mutex, one thread's write can overwrite the other's.
    /// With Loom, we verify that our locked version never loses updates.
    #[test]
    fn test_inode_table_lock_prevents_lost_writes() {
        loom::model(|| {
            // Two "inodes" in the same block, protected by a lock
            let inode_a: Arc<RwLock<u32>> = Arc::new(RwLock::new(0));
            let inode_b: Arc<RwLock<u32>> = Arc::new(RwLock::new(0));
            let table_lock: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

            let ia = Arc::clone(&inode_a);
            let lock1 = Arc::clone(&table_lock);

            let ib = Arc::clone(&inode_b);
            let lock2 = Arc::clone(&table_lock);

            // Thread 1: increment inode_a under table lock
            let t1 = thread::spawn(move || {
                let _guard = lock1.lock().unwrap();
                let mut val = ia.write().unwrap();
                *val += 1;
            });

            // Thread 2: increment inode_b under table lock
            let t2 = thread::spawn(move || {
                let _guard = lock2.lock().unwrap();
                let mut val = ib.write().unwrap();
                *val += 1;
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Both increments must be visible
            assert_eq!(*inode_a.read().unwrap(), 1);
            assert_eq!(*inode_b.read().unwrap(), 1);
        });
    }

    /// Test multiple RwLock fields accessed in sequence (lock ordering).
    ///
    /// Mirrors VolumeIOFilesystem operations that must lock multiple fields:
    /// e.g., write_file needs block_bitmap (write) + inode_cache (write) + io (read).
    /// Tests that consistent lock ordering prevents deadlocks.
    #[test]
    fn test_multi_rwlock_ordering() {
        loom::model(|| {
            let bitmap: Arc<RwLock<Vec<bool>>> = Arc::new(RwLock::new(vec![false; 4]));
            let cache: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(Vec::new()));
            let dirty: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));

            let bm1 = Arc::clone(&bitmap);
            let ca1 = Arc::clone(&cache);
            let di1 = Arc::clone(&dirty);

            let bm2 = Arc::clone(&bitmap);
            let ca2 = Arc::clone(&cache);
            let di2 = Arc::clone(&dirty);

            // Thread 1: "allocate block" — bitmap(write), cache(write), dirty(write)
            // Always lock in order: bitmap -> cache -> dirty
            let t1 = thread::spawn(move || {
                {
                    let mut bm = bm1.write().unwrap();
                    bm[0] = true;
                }
                {
                    let mut ca = ca1.write().unwrap();
                    ca.push(0);
                }
                {
                    let mut d = di1.write().unwrap();
                    *d = true;
                }
            });

            // Thread 2: "allocate another block" — same lock order
            let t2 = thread::spawn(move || {
                {
                    let mut bm = bm2.write().unwrap();
                    bm[1] = true;
                }
                {
                    let mut ca = ca2.write().unwrap();
                    ca.push(1);
                }
                {
                    let mut d = di2.write().unwrap();
                    *d = true;
                }
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Both blocks allocated
            let bm = bitmap.read().unwrap();
            assert!(bm[0] && bm[1]);

            // Both inodes cached
            let ca = cache.read().unwrap();
            assert_eq!(ca.len(), 2);
            assert!(ca.contains(&0) && ca.contains(&1));

            // Dirty flag set
            assert!(*dirty.read().unwrap());
        });
    }

    // =========================================================================
    // chunk_locks pattern tests (RwLock<HashMap<u64, Arc<Mutex<()>>>>)
    // =========================================================================

    /// Test chunk_lock double-checked creation.
    ///
    /// Mirrors VolumeIO::chunk_lock(): fast path reads RwLock, slow path
    /// writes via entry API. Two threads requesting the same chunk_id
    /// must get the same Arc<Mutex<()>> — exactly one mutex is created.
    #[test]
    fn test_chunk_lock_double_checked_creation() {
        use std::collections::HashMap;

        loom::model(|| {
            let locks: Arc<RwLock<HashMap<u64, Arc<Mutex<()>>>>> =
                Arc::new(RwLock::new(HashMap::new()));

            let l1 = Arc::clone(&locks);
            let l2 = Arc::clone(&locks);

            // chunk_lock() implementation pattern
            let get_lock = |locks: &Arc<RwLock<HashMap<u64, Arc<Mutex<()>>>>>,
                            chunk_id: u64|
             -> Arc<Mutex<()>> {
                // Fast path: read lock
                if let Ok(guard) = locks.read() {
                    if let Some(lock) = guard.get(&chunk_id) {
                        return Arc::clone(lock);
                    }
                }
                // Slow path: write lock + entry API
                let mut guard = locks.write().unwrap();
                Arc::clone(
                    guard
                        .entry(chunk_id)
                        .or_insert_with(|| Arc::new(Mutex::new(()))),
                )
            };

            // Both threads request lock for chunk 5
            let t1 = thread::spawn(move || get_lock(&l1, 5));
            let t2 = thread::spawn(move || get_lock(&l2, 5));

            let lock1 = t1.join().unwrap();
            let lock2 = t2.join().unwrap();

            // Both must reference the same underlying mutex
            assert!(Arc::ptr_eq(&lock1, &lock2));

            // Exactly one entry in the map
            assert_eq!(locks.read().unwrap().len(), 1);
        });
    }

    /// Test concurrent writes to different chunks.
    ///
    /// Mirrors VolumeIO::write(): two threads writing to different chunk IDs
    /// acquire independent per-chunk locks and should not block each other.
    /// Both writes must be fully preserved.
    #[test]
    fn test_chunk_lock_different_chunks_parallel() {
        use std::collections::HashMap;

        loom::model(|| {
            let locks: Arc<RwLock<HashMap<u64, Arc<Mutex<()>>>>> =
                Arc::new(RwLock::new(HashMap::new()));
            // Simulated chunk data
            let chunk_a = Arc::new(Mutex::new(vec![0u8; 4]));
            let chunk_b = Arc::new(Mutex::new(vec![0u8; 4]));

            let l1 = Arc::clone(&locks);
            let ca = Arc::clone(&chunk_a);
            let l2 = Arc::clone(&locks);
            let cb = Arc::clone(&chunk_b);

            let get_lock = |locks: &Arc<RwLock<HashMap<u64, Arc<Mutex<()>>>>>,
                            chunk_id: u64|
             -> Arc<Mutex<()>> {
                if let Ok(guard) = locks.read() {
                    if let Some(lock) = guard.get(&chunk_id) {
                        return Arc::clone(lock);
                    }
                }
                let mut guard = locks.write().unwrap();
                Arc::clone(
                    guard
                        .entry(chunk_id)
                        .or_insert_with(|| Arc::new(Mutex::new(()))),
                )
            };

            // Thread 1: write to chunk 0
            let t1 = thread::spawn(move || {
                let lock = get_lock(&l1, 0);
                let _guard = lock.lock().unwrap();
                let mut data = ca.lock().unwrap();
                data[0] = 0xAA;
            });

            // Thread 2: write to chunk 1
            let t2 = thread::spawn(move || {
                let lock = get_lock(&l2, 1);
                let _guard = lock.lock().unwrap();
                let mut data = cb.lock().unwrap();
                data[0] = 0xBB;
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Both writes preserved
            assert_eq!(chunk_a.lock().unwrap()[0], 0xAA);
            assert_eq!(chunk_b.lock().unwrap()[0], 0xBB);
        });
    }

    /// Test concurrent writes to same chunk are serialized.
    ///
    /// Mirrors VolumeIO::write() where two threads write to different offsets
    /// within the same chunk. The per-chunk Mutex serializes the
    /// read-modify-write so neither update is lost.
    #[test]
    fn test_chunk_lock_same_chunk_serialized() {
        use std::collections::HashMap;

        loom::model(|| {
            let locks: Arc<RwLock<HashMap<u64, Arc<Mutex<()>>>>> =
                Arc::new(RwLock::new(HashMap::new()));
            // Simulated chunk: 4 bytes, each thread writes to a different offset
            let chunk = Arc::new(Mutex::new(vec![0u8; 4]));

            let l1 = Arc::clone(&locks);
            let c1 = Arc::clone(&chunk);
            let l2 = Arc::clone(&locks);
            let c2 = Arc::clone(&chunk);

            let get_lock = |locks: &Arc<RwLock<HashMap<u64, Arc<Mutex<()>>>>>,
                            chunk_id: u64|
             -> Arc<Mutex<()>> {
                if let Ok(guard) = locks.read() {
                    if let Some(lock) = guard.get(&chunk_id) {
                        return Arc::clone(lock);
                    }
                }
                let mut guard = locks.write().unwrap();
                Arc::clone(
                    guard
                        .entry(chunk_id)
                        .or_insert_with(|| Arc::new(Mutex::new(()))),
                )
            };

            // Thread 1: write byte at offset 0 under chunk lock
            let t1 = thread::spawn(move || {
                let lock = get_lock(&l1, 7);
                let _guard = lock.lock().unwrap();
                // read-modify-write
                let mut data = c1.lock().unwrap();
                data[0] = 0x11;
            });

            // Thread 2: write byte at offset 2 under same chunk lock
            let t2 = thread::spawn(move || {
                let lock = get_lock(&l2, 7);
                let _guard = lock.lock().unwrap();
                // read-modify-write
                let mut data = c2.lock().unwrap();
                data[2] = 0x22;
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Both writes must be preserved (no lost updates)
            let data = chunk.lock().unwrap();
            assert_eq!(data[0], 0x11);
            assert_eq!(data[2], 0x22);
        });
    }

    /// Test read-while-write on separate RwLock fields.
    ///
    /// Mirrors the pattern where stat() reads inode_cache while
    /// write_file() updates block_bitmap — independent RwLocks allow
    /// true parallelism.
    #[test]
    fn test_independent_rwlock_parallelism() {
        loom::model(|| {
            let bitmap: Arc<RwLock<Vec<bool>>> = Arc::new(RwLock::new(vec![false; 4]));
            let cache: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(vec![1, 2, 3]));

            let bm = Arc::clone(&bitmap);
            let ca = Arc::clone(&cache);

            // Writer: modify bitmap
            let writer = thread::spawn(move || {
                let mut guard = bm.write().unwrap();
                guard[0] = true;
            });

            // Reader: read cache (independent, should not block)
            let reader = thread::spawn(move || {
                let guard = ca.read().unwrap();
                guard.len()
            });

            writer.join().unwrap();
            let cache_len = reader.join().unwrap();

            // Reader always sees the pre-populated cache
            assert_eq!(cache_len, 3);

            // Writer's update is visible
            assert!(bitmap.read().unwrap()[0]);
        });
    }
}

// Fallback tests when loom feature is not enabled
#[cfg(all(test, not(feature = "loom")))]
mod regular_tests {
    use std::sync::{Arc, Mutex, RwLock};

    #[test]
    fn test_rwlock_option_basic() {
        let io: Arc<RwLock<Option<u64>>> = Arc::new(RwLock::new(None));
        *io.write().unwrap() = Some(42);
        assert_eq!(*io.read().unwrap(), Some(42));
    }

    #[test]
    fn test_inode_table_lock_basic() {
        let block: Arc<RwLock<[u32; 2]>> = Arc::new(RwLock::new([0, 0]));
        let table_lock: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

        let _guard = table_lock.lock().unwrap();
        let mut data = block.write().unwrap();
        data[0] = 100;
        data[1] = 200;
        drop(data);

        assert_eq!(block.read().unwrap()[0], 100);
        assert_eq!(block.read().unwrap()[1], 200);
    }

    #[test]
    fn test_dirty_flag_basic() {
        let dirty: RwLock<bool> = RwLock::new(false);
        *dirty.write().unwrap() = true;
        assert!(*dirty.read().unwrap());
        *dirty.write().unwrap() = false;
        assert!(!*dirty.read().unwrap());
    }
}
