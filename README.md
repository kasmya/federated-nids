# NIDS Web Dashboard

A modern, web-based Network Intrusion Detection System with real-time monitoring.

## Features

- 🌐 **Web-based Interface** - Modern UI accessible from any browser
- ⚡ **Real-time Capture** - Live packet capture using Scapy
- 🔍 **Rule-based Detection** - Custom rules with CIDR support
- 📊 **Protocol Statistics** - Live protocol distribution
- 💾 **PCAP Support** - Load and save packet captures
- 🎨 **Matrix Theme** - Cybersecurity-inspired dark UI

## Quick Start

```bash
cd nids-web-dashboard

# Install dependencies (if needed)
pip3 install flask scapy pyshark

# Start the server
python3 run_server.py

# Or use the start script
chmod +x start.sh
./start.sh
```

Then open http://localhost:5000 in your browser.

## Usage

### Interface Selection
1. Select a network interface from the dropdown
2. Click **START** to begin capture

### View Traffic
- **ALL TRAFFIC** tab shows captured packets
- **SECURITY ALERTS** shows rule matches

### PCAP Files
- Click **LOAD PCAP** to upload existing captures
- Click **SAVE CAPTURE** to save current session

### Rules Format
Rules are in `rules.txt`:
```
alert [proto] [srcip] [srcport] --> [dstip] [dstport] [message]
```

Examples:
```
alert tcp any any --> any 22 SSH_DETECTED
alert tcp 192.168.1.0/24 any --> any any INTERNAL_SCAN
alert udp any any --> any 53 SUSPICIOUS_DNS
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Get capture status |
| `/api/interfaces` | GET | List network interfaces |
| `/api/rules` | GET | Get detection rules |
| `/api/alerts` | GET | Get security alerts |
| `/api/protocols` | GET | Get protocol statistics |
| `/api/capture` | POST | Start/stop capture |
| `/api/upload_pcap` | POST | Upload PCAP file |
| `/api/save_pcap` | POST | Save capture to file |

## Files

```
nids-web-dashboard/
├── run_server.py      # Main server launcher
├── nids_server.py     # Flask application
├── requirements.txt   # Dependencies
├── rules.txt         # Detection rules
├── templates/
│   └── index.html    # Dashboard UI
├── static/
│   ├── css/style.css # Matrix theme
│   └── js/
│       ├── app.js    # Frontend logic
│       └── matrix.js # Rain animation
└── saved_pcap/       # Saved captures
```

## Requirements

- Python 3.8+
- macOS, Linux, or Windows
- Network interface access
- Admin/root for capture

## Troubleshooting

**Permission Denied:**
```bash
sudo python3 run_server.py
```

**Interface Not Found:**
- Check interfaces with `ifconfig` or `ip link`
- The dashboard will show available interfaces

**Capture Not Starting:**
- Verify no other process is using the interface
- Check firewall settings

## License

MIT License

