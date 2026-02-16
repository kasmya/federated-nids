# Render Deployment Guide

## Quick Deploy

Click the button below to deploy to Render:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/kasmya/hybrid-closedloop-nids)

## Manual Deployment

### Option 1: From Render Dashboard

1. Go to [render.com](https://render.com) and sign up/login
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: nids-closed-loop
   - **Environment**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python3 run_server.py`
5. Click "Create Web Service"

### Option 2: From Command Line (after installing render-cli)

```bash
render deploy
```

## Important Notes

### Packet Capture Limitations
- **Render cloud servers cannot capture live network packets**
- The web interface will work, but real-time capture requires:
  - Running locally with sudo/admin privileges
  - Or uploading PCAP files for analysis

### Features that work on Render:
- ✅ Web dashboard UI
- ✅ PCAP file upload and analysis
- ✅ Rule-based detection
- ✅ Anomaly detection on uploaded files
- ✅ YARA scanning

### Features that require local deployment:
- ❌ Live packet capture
- ❌ Real-time network monitoring

## Environment Variables

The following are automatically set by Render:
- `PORT` - Port number (default: 10000)
- `PYTHON_VERSION` - Python version

## Troubleshooting

### Build fails
- Make sure requirements.txt has compatible package versions
- Avoid packages that require compilation (yara-python may need adjustments)

### App won't start
- Check logs in Render dashboard
- Ensure start command matches: `python3 run_server.py`

### Performance
- Free tier has limited CPU/memory
- Consider upgrading for production use

