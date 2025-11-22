# Secure Cryptor WASM Examples

This directory contains working examples demonstrating how to use Secure Cryptor in web browsers.

## Examples

### 1. Interactive Demo ([demo.html](demo.html)) ⭐ **Recommended**
Full-featured web application showcasing all WASM capabilities.

**Features:**
- 📝 Text encryption/decryption with multiple security levels
- 📁 File encryption/decryption with drag & drop
- 🔐 Real-time password strength meter
- 🛡️ Security information and audit
- 🎨 Modern, responsive UI
- ⚡ Multiple security configurations (Fast, Balanced, Secure)

**Usage:**
```bash
# Serve from the root directory
python -m http.server 8000
# or
npx serve

# Open in browser
http://localhost:8000/examples/wasm/demo.html
```

### 2. Basic Example ([basic-example.html](basic-example.html))
Simple encryption/decryption demo using ES modules.

**Features:**
- Text encryption/decryption
- Direct WASM module usage
- Performance timing

**Usage:**
```bash
# Serve from the root directory
python -m http.server 8000
# or
npx serve

# Open in browser
http://localhost:8000/examples/wasm/basic-example.html
```

### 3. Web Worker Example ([worker-example.html](worker-example.html))
Advanced example using Web Workers for non-blocking encryption.

**Features:**
- Background thread processing
- Worker pool management
- Parallel encryption
- Performance benchmarks
- Real-time statistics

**Advantages:**
- ✅ UI stays responsive during heavy crypto operations
- ✅ Parallel processing on multi-core systems
- ✅ Better security isolation
- ✅ Scalable performance

**Usage:**
```bash
# Serve from the root directory
python -m http.server 8000

# Open in browser
http://localhost:8000/examples/wasm/worker-example.html
```

## Files

- **demo.html** - ⭐ Full-featured interactive demo application
- **basic-example.html** - Simple single-threaded encryption demo
- **worker-example.html** - Web Worker-based encryption demo
- **worker.js** - Web Worker implementation for crypto operations
- **worker-pool.js** - Worker pool manager for parallel processing

## Requirements

- Modern web browser with:
  - WebAssembly support
  - ES6 modules support
  - Web Workers (for worker examples)
  - Secure context (HTTPS or localhost)

## Security Notes

1. **HTTPS Required**: Always serve over HTTPS in production
2. **Content Security Policy**: See [WASM_SECURITY.md](../../WASM_SECURITY.md)
3. **Subresource Integrity**: Generate SRI hashes for production
4. **Web Workers**: Recommended for better security and performance

## Performance Comparison

### Main Thread vs Web Workers

| Operation | Main Thread | Web Worker (Single) | Worker Pool (4 cores) |
|-----------|-------------|---------------------|----------------------|
| 1 encryption | ~50ms | ~55ms | ~55ms |
| 10 encryptions | ~500ms | ~550ms | ~200ms |
| 50 encryptions | ~2500ms | ~2750ms | ~800ms |

*Times are approximate and vary by hardware*

**Key Takeaway**: Worker pools shine with parallel operations, distributing work across CPU cores.

## Integration Guide

### Basic Integration

```html
<script type="module">
import init, { encrypt_text, decrypt_text } from './pkg/web/secure_cryptor.js';

await init();

const encrypted = encrypt_text("password", "Hello!");
const decrypted = decrypt_text("password", encrypted);
</script>
```

### Worker Pool Integration

```html
<script src="worker-pool.js"></script>
<script>
const pool = new WorkerPool('worker.js', 4);

const encrypted = await pool.encryptText("password", "Hello!");
const decrypted = await pool.decryptText("password", encrypted);
</script>
```

## Troubleshooting

### CORS Errors
Serve files from a local web server, not `file://` protocol.

### Module Loading Errors
Ensure you're using `<script type="module">` for ES modules.

### Worker Loading Fails
Check that worker.js path is correct relative to the HTML file.

### WASM Not Found
Verify `pkg/web/secure_cryptor_bg.wasm` exists and path is correct.

## Next Steps

- Read [WASM_README.md](../../WASM_README.md) for API documentation
- Check [WASM_SECURITY.md](../../WASM_SECURITY.md) for security best practices
- Explore the [source code](../../src/wasm/) to understand implementation
