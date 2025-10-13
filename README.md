# Simple-Network-Scanner
A simple network scanner using Pyhton's socket library
## Network Scanner (Scapy)

Simple ARP sweep with optional TCP SYN scan, built with Scapy. Great as a minimal example project.

### Features
- ARP sweep across a CIDR (e.g., `192.168.1.0/24`)
- Optional TCP SYN scan for specified ports
- Interface selection and timeouts
- Lazy Scapy import, so `--help` works without installing deps

### Requirements
- Python 3.10+
- Scapy (`pip install -r requirements.txt`)
- Root privileges for ARP and SYN scanning (use `sudo`)

### Install
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage
```bash
# ARP sweep the local /24
sudo python scanner.py 192.168.1.0/24

# ARP sweep and TCP SYN scan ports 22,80,443
sudo python scanner.py 192.168.1.0/24 --tcp-ports 22,80,443

# TCP SYN scan a range only (skip ARP)
sudo python scanner.py 192.168.1.0/24 --tcp-ports 1-1024 --no-arp

# Specify interface
sudo python scanner.py 192.168.1.0/24 --iface eth0 --tcp-ports 22-25
```
## Notes
This scanner is easily bypassable through a couple tools, only made for demonstration purposes

### Legal and Ethical Notice
Only scan networks you own or have explicit permission to test.
