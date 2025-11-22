/**
 * Secure Cryptor Web Worker
 *
 * This worker runs encryption/decryption operations in a background thread,
 * preventing UI blocking during heavy cryptographic operations.
 */

importScripts('../../pkg/web/secure_cryptor.js');

const { encrypt_text, decrypt_text, encrypt_bytes, decrypt_bytes, EncryptConfig, security_audit_info } = wasm_bindgen;

let initialized = false;

/**
 * Initialize the WASM module
 */
async function init() {
    if (!initialized) {
        await wasm_bindgen('../../pkg/web/secure_cryptor_bg.wasm');
        initialized = true;
    }
}

/**
 * Message handler for worker commands
 */
self.onmessage = async function(e) {
    const { id, command, data } = e.data;

    try {
        // Ensure WASM is initialized
        if (!initialized) {
            await init();
        }

        let result;

        switch (command) {
            case 'encrypt_text':
                result = encrypt_text(data.password, data.plaintext);
                break;

            case 'decrypt_text':
                result = decrypt_text(data.password, data.ciphertext);
                break;

            case 'encrypt_bytes':
                result = encrypt_bytes(data.password, data.bytes);
                break;

            case 'decrypt_bytes':
                result = decrypt_bytes(data.password, data.bytes);
                break;

            case 'encrypt_text_with_config':
                const encryptConfig = data.config || EncryptConfig.balanced();
                result = wasm_bindgen.encrypt_text_with_config(
                    data.password,
                    data.plaintext,
                    encryptConfig
                );
                break;

            case 'decrypt_text_with_config':
                const decryptConfig = data.config || EncryptConfig.balanced();
                result = wasm_bindgen.decrypt_text_with_config(
                    data.password,
                    data.ciphertext,
                    decryptConfig
                );
                break;

            case 'security_audit':
                result = security_audit_info();
                break;

            default:
                throw new Error(`Unknown command: ${command}`);
        }

        // Send success response
        self.postMessage({
            id,
            success: true,
            result
        });

    } catch (error) {
        // Send error response
        self.postMessage({
            id,
            success: false,
            error: error.message || String(error)
        });
    }
};

// Signal that worker is ready
self.postMessage({ type: 'ready' });
