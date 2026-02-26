# Aegis-Prime Vercel Deployment Guide

## Overview

This guide explains how to deploy Aegis-Prime Web Dashboard to Vercel, a serverless platform optimized for Python applications.

## Prerequisites

1. **GitHub Repository**: Push your code to GitHub
2. **Vercel Account**: Sign up at https://vercel.com
3. **Python 3.9+**: Required for serverless functions
4. **Git**: For pushing changes

## Deployment Steps

### Step 1: Push to GitHub

```bash
cd e:\AMD\Aegis-Prime
git add .
git commit -m "feat: Prepare for Vercel deployment with serverless structure"
git push origin main
```

### Step 2: Connect to Vercel

1. Go to https://vercel.com/new
2. Click "Continue with GitHub"
3. Authorize Vercel to access your GitHub account
4. Select the `AMD` repository
5. Click "Import"

### Step 3: Configure Project Settings

**Project Name:** `aegis-prime` (or your preferred name)

**Framework Preset:** Python (should auto-detect)

**Root Directory:** ./Aegis-Prime

**Build Command:** (Leave empty - Vercel auto-detects)

**Install Command:** (Leave empty - Vercel auto-detects)

**Output Directory:** (Leave empty)

### Step 4: Environment Variables (Optional)

If you need custom environment variables:

1. Go to Settings → Environment Variables
2. Add any custom variables (e.g., `SUBSTRATE_ENDPOINT`, etc.)
3. Click Save

### Step 5: Deploy

1. Click "Deploy"
2. Wait for build to complete (usually 2-3 minutes)
3. Once complete, you'll get a deployment URL

## Project Structure for Vercel

```
Aegis-Prime/
├── api/
│   └── index.py              # Serverless entry point (WSGI app)
├── core/
│   ├── __init__.py
│   ├── cypher_shield.py
│   ├── zenith_mesh.py
│   ├── lumina_auth.py
│   └── synapse_kernel.py
├── templates/
│   └── dashboard.html        # Frontend UI
├── main.py                   # Orchestrator logic
├── web_dashboard.py          # Legacy local server (for development)
├── vercel.json              # Vercel configuration
├── .vercelignore            # Files to exclude from deploy
├── requirements.txt         # Python dependencies
└── README.md
```

## How Vercel Deployment Works

### Serverless Functions

- `api/index.py` is converted to a serverless function
- Each request is handled by a Vercel Function
- Flask app is exposed via the `app` variable

### Routing

All requests are routed to `api/index.py`:
- GET `/` → Serves dashboard.html
- POST `/api/handshake-stream` → Real-time SSE endpoint
- POST `/api/handshake` → Legacy handshake endpoint
- GET `/api/health` → Health check
- GET `/health` → Deployment health check

### Static Files

Templates are embedded within the Flask app using the `template_folder` parameter pointing to the local `templates/` directory.

## Limitations & Considerations

### Timeout
- Vercel functions timeout after 60 seconds (Pro) or 10 seconds (free)
- Long-running Aegis handshakes may need optimization
- Consider breaking down phases into async tasks

### Memory
- Default: 512MB (Pro: 3008MB)
- Sufficient for Aegis-Prime operations

### Cold Starts
- First request may take 1-2 seconds (warm-up)
- Subsequent requests are fast

### Environment
- Vercel uses Ubuntu Linux environment
- Python 3.9+ available
- Some C-compiled libraries may have compatibility issues

## Environment Variables

Create a `.env.local` file for local development:

```bash
SUBSTRATE_ENDPOINT=ws://localhost:9944
FLASK_ENV=development
```

For Vercel deployment, add variables via Dashboard:
1. Settings → Environment Variables
2. Add variable and select which environments (Production/Preview)

## Testing Before Deploy

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally with Vercel CLI
npm install -g vercel
vercel dev
```

### Production Build Test

```bash
vercel build
vercel start
```

## Troubleshooting

### "Module not found" errors

Ensure all imports use proper paths. The `api/index.py` file adds the parent directory to `sys.path`:

```python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
```

### Template not found

Templates are loaded from `templates/` directory relative to the Flask app root. Ensure `dashboard.html` exists in `Aegis-Prime/templates/`.

### Timeout errors

If the Aegis handshake exceeds 60s:
1. Optimize phase execution
2. Use streaming responses (SSE)
3. Consider upgrading to Vercel Pro for extended timeout

### Memory issues

If you hit memory limits:
1. Check which operations are memory-intensive
2. Optimize buffer.db encryption
3. Clear old receipts from database

## Custom Domain

1. Go to Settings → Domains
2. Add your custom domain
3. Follow DNS configuration instructions
4. Wait for propagation (usually 24-48 hours)

## Monitoring & Logs

1. Go to your project's dashboard
2. Click "Deployments"
3. Select a deployment
4. View "Function Logs" in real-time

## Continuous Deployment

Once connected to GitHub:
- **Production**: Deploy on push to `main` branch
- **Preview**: Deploy on pull requests
- **Staging**: Configure branch-specific deployments

To disable auto-deploy:
1. Settings → Git
2. Uncheck "Deploy on push"

## Rollback

To rollback to a previous deployment:

1. Go to Deployments
2. Click the deployment you want to restore
3. Click the "..." menu
4. Select "Promote to Production"

## Performance Optimization

### Tips for faster deployments

1. **Reduce bundle size**: Remove unused dependencies
2. **Cache dependencies**: Vercel caches packages automatically
3. **Optimize imports**: Lazy-load heavy modules
4. **Use environment variables**: Avoid hardcoding configs

### API optimization

```python
# Use streaming for long operations
@app.route('/api/handshake-stream', methods=['POST'])
def handshake_stream():
    return Response(event_generator(), mimetype='text/event-stream')
```

## Security

1. **HTTPS**: Automatic with Vercel's SSL certificate
2. **Environment variables**: Never commit secrets
3. **Rate limiting**: Consider adding rate limiters in production
4. **CORS**: Configure if needed

```python
from flask_cors import CORS
CORS(app)
```

## Cost Estimation

**Vercel Pricing (as of 2026)**:
- **Hobby Plan** (Free): Great for testing
  - Limited requests/month
  - 10s timeout
  - No production support

- **Pro Plan** ($20/month): Recommended
  - Unlimited function invocations
  - 60s timeout
  - Higher memory limits
  - Priority support

- **Enterprise**: Custom pricing

## Support & Resources

- **Documentation**: https://vercel.com/docs
- **Python Guide**: https://vercel.com/docs/functions/runtimes/python
- **Discord Community**: https://discord.gg/vercel
- **GitHub Issues**: Report bugs in your repository

## Next Steps

1. **Test locally**: Run `vercel dev`
2. **Deploy**: Connect GitHub and push to main
3. **Monitor**: Check logs and performance
4. **Optimize**: Refine based on metrics
5. **Scale**: Upgrade plan if needed

---

**Deployment Date**: February 26, 2026
**Status**: Production Ready
**Framework**: Flask + Python
**Platform**: Vercel Serverless Functions
