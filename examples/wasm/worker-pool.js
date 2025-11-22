/**
 * Web Worker Pool Manager
 *
 * Manages a pool of Web Workers for parallel encryption/decryption operations.
 * Automatically distributes work across available workers.
 */

class WorkerPool {
    constructor(workerScript, poolSize = navigator.hardwareConcurrency || 4) {
        this.workerScript = workerScript;
        this.poolSize = poolSize;
        this.workers = [];
        this.availableWorkers = [];
        this.queue = [];
        this.nextId = 0;

        this.initialize();
    }

    /**
     * Initialize the worker pool
     */
    initialize() {
        for (let i = 0; i < this.poolSize; i++) {
            const worker = new Worker(this.workerScript);

            worker.onmessage = (e) => this.handleWorkerMessage(worker, e);
            worker.onerror = (e) => this.handleWorkerError(worker, e);

            this.workers.push(worker);
        }
    }

    /**
     * Handle messages from workers
     */
    handleWorkerMessage(worker, event) {
        const message = event.data;

        // Worker ready signal
        if (message.type === 'ready') {
            this.availableWorkers.push(worker);
            this.processQueue();
            return;
        }

        // Task result
        if (message.id !== undefined) {
            const callback = worker.currentCallback;
            if (callback) {
                if (message.success) {
                    callback.resolve(message.result);
                } else {
                    callback.reject(new Error(message.error));
                }
                worker.currentCallback = null;
            }

            // Return worker to pool
            this.availableWorkers.push(worker);
            this.processQueue();
        }
    }

    /**
     * Handle worker errors
     */
    handleWorkerError(worker, error) {
        console.error('Worker error:', error);

        if (worker.currentCallback) {
            worker.currentCallback.reject(error);
            worker.currentCallback = null;
        }

        // Return worker to pool
        this.availableWorkers.push(worker);
        this.processQueue();
    }

    /**
     * Process queued tasks
     */
    processQueue() {
        while (this.queue.length > 0 && this.availableWorkers.length > 0) {
            const task = this.queue.shift();
            const worker = this.availableWorkers.shift();

            worker.currentCallback = {
                resolve: task.resolve,
                reject: task.reject
            };

            worker.postMessage(task.message);
        }
    }

    /**
     * Execute a task on an available worker
     */
    execute(command, data) {
        return new Promise((resolve, reject) => {
            const id = this.nextId++;
            const message = { id, command, data };

            const task = { message, resolve, reject };

            if (this.availableWorkers.length > 0) {
                const worker = this.availableWorkers.shift();
                worker.currentCallback = { resolve, reject };
                worker.postMessage(message);
            } else {
                this.queue.push(task);
            }
        });
    }

    /**
     * Convenience methods for common operations
     */
    encryptText(password, plaintext, config = null) {
        return this.execute('encrypt_text_with_config', {
            password,
            plaintext,
            config
        });
    }

    decryptText(password, ciphertext, config = null) {
        return this.execute('decrypt_text_with_config', {
            password,
            ciphertext,
            config
        });
    }

    encryptBytes(password, bytes) {
        return this.execute('encrypt_bytes', { password, bytes });
    }

    decryptBytes(password, bytes) {
        return this.execute('decrypt_bytes', { password, bytes });
    }

    getSecurityAudit() {
        return this.execute('security_audit', {});
    }

    /**
     * Terminate all workers
     */
    terminate() {
        this.workers.forEach(worker => worker.terminate());
        this.workers = [];
        this.availableWorkers = [];
        this.queue = [];
    }

    /**
     * Get pool statistics
     */
    getStats() {
        return {
            poolSize: this.poolSize,
            availableWorkers: this.availableWorkers.length,
            queuedTasks: this.queue.length,
            busyWorkers: this.poolSize - this.availableWorkers.length
        };
    }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WorkerPool;
}
