# GitHub Pages Deployment Guide

This guide explains how to deploy the Secure Cryptor WASM demo to GitHub Pages.

## Prerequisites

1. GitHub repository with this codebase
2. WASM package built (`wasm-pack build --target web --out-dir pkg/web`)
3. Git installed and configured

## Deployment Steps

### Option 1: GitHub Actions (Recommended)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown

      - name: Install wasm-pack
        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

      - name: Build WASM
        run: wasm-pack build --target web --out-dir pkg/web

      - name: Setup Pages
        uses: actions/configure-pages@v4

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: 'examples/wasm'

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

**Enable GitHub Pages:**
1. Go to repository Settings → Pages
2. Source: GitHub Actions
3. Wait for deployment to complete
4. Visit: `https://yourusername.github.io/secure-cryptor/`

### Option 2: Manual gh-pages Branch

```bash
# 1. Build WASM package
wasm-pack build --target web --out-dir pkg/web

# 2. Create gh-pages branch
git checkout --orphan gh-pages

# 3. Remove all files except what we need
git rm -rf .
git clean -fxd

# 4. Copy only necessary files
git checkout main -- examples/wasm/
git checkout main -- pkg/web/
git checkout main -- .nojekyll

# 5. Move files to root
mv examples/wasm/* .
rmdir examples/wasm
rmdir examples

# 6. Commit and push
git add .
git commit -m "Deploy to GitHub Pages"
git push origin gh-pages

# 7. Return to main branch
git checkout main
```

**Enable GitHub Pages:**
1. Go to repository Settings → Pages
2. Source: Deploy from a branch
3. Branch: gh-pages / (root)
4. Visit: `https://yourusername.github.io/secure-cryptor/`

### Option 3: Subtree Deploy

```bash
# 1. Build WASM
wasm-pack build --target web --out-dir pkg/web

# 2. Create deployment directory
mkdir -p deploy
cp -r examples/wasm/* deploy/
cp -r pkg/web deploy/pkg/web
cp .nojekyll deploy/

# 3. Deploy subtree
git subtree push --prefix deploy origin gh-pages

# 4. Clean up
rm -rf deploy
```

## Files Included in Deployment

- `index.html` - Entry point (redirects to demo.html)
- `demo.html` - Interactive demo application
- `basic-example.html` - Simple example
- `worker-example.html` - Web Worker example
- `worker.js` - Web Worker implementation
- `worker-pool.js` - Worker pool manager
- `README.md` - Documentation
- `pkg/web/` - WASM binaries and JavaScript bindings
- `.nojekyll` - Prevents Jekyll processing

## Security Considerations

### Content Security Policy

When deploying to production, add CSP headers. For GitHub Pages, you can't set HTTP headers, but you can use a meta tag in your HTML:

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self';">
```

### Subresource Integrity

Generate SRI hashes for your WASM files:

```bash
# Generate SHA-384 hash
openssl dgst -sha384 -binary pkg/web/secure_cryptor_bg.wasm | openssl base64 -A
```

Add to your script tags:
```html
<script type="module"
        src="pkg/web/secure_cryptor.js"
        integrity="sha384-..."
        crossorigin="anonymous">
</script>
```

### HTTPS

GitHub Pages automatically serves over HTTPS. Ensure all resources are loaded via HTTPS.

## Troubleshooting

### WASM File Not Found

Ensure paths in HTML files are correct:
```javascript
import init from './pkg/web/secure_cryptor.js';
await init(); // Defaults to secure_cryptor_bg.wasm in same directory
```

### CORS Issues

GitHub Pages sets appropriate CORS headers. If testing locally, use:
```bash
python -m http.server 8000
# or
npx serve
```

### Module Loading Errors

Verify you're using:
```html
<script type="module">
```

### Worker Loading Fails

Check worker paths are relative to the HTML file location.

## Custom Domain

To use a custom domain:

1. Add `CNAME` file to deployment:
```bash
echo "crypto.yourdomain.com" > CNAME
git add CNAME
git commit -m "Add custom domain"
git push origin gh-pages
```

2. Configure DNS:
```
Type: CNAME
Name: crypto
Value: yourusername.github.io
```

3. Enable HTTPS in GitHub Pages settings

## Monitoring

Monitor your deployment at:
- GitHub Actions: `https://github.com/yourusername/secure-cryptor/actions`
- GitHub Pages: Settings → Pages

## Performance Optimization

The WASM binary is currently 134KB. For optimization tips, see:
- [Optimize WASM bundle size](#) (coming soon)
- Run `wasm-opt` for size reduction
- Enable gzip compression (automatic on GitHub Pages)

## Example Live Deployments

- Demo: `https://yourusername.github.io/secure-cryptor/demo.html`
- Basic: `https://yourusername.github.io/secure-cryptor/basic-example.html`
- Worker: `https://yourusername.github.io/secure-cryptor/worker-example.html`

## Updating Deployment

To update your deployment:

```bash
# GitHub Actions: Just push to main
git push origin main

# Manual: Repeat deployment steps
# Subtree: Run subtree push again
```

## Rolling Back

To rollback to a previous version:

```bash
git checkout gh-pages
git reset --hard <commit-hash>
git push --force origin gh-pages
```

## Support

For issues:
1. Check browser console for errors
2. Verify WASM files are being served correctly
3. Test locally before deploying
4. Check GitHub Actions logs for build errors

## License

Deployed content follows the same license as the repository.
