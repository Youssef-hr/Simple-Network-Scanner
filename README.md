# Simple-Network-Scanner
A simple network scanner using Pyhton's socket library
## Network Scanner (Scapy)

- Simple ARP sweep with optional TCP SYN scan, built with Scapy. Great as a minimal example project.
- I'd advise you to use Nmap or Metasploit throughout the resconissance process, this is a learning project 
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
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage
```bash
# ARP sweep the local /24
sudo /full/path/to/venv/python scanner.py 192.168.1.0/24

# ARP sweep and TCP SYN scan ports 22,80,443
sudo /full/path/to/venv/python scanner.py 192.168.1.0/24 --tcp-ports 22,80,443

# TCP SYN scan a range only (skip ARP)
sudo /full/path/to/venv/python scanner.py 192.168.1.0/24 --tcp-ports 1-1024 --no-arp

# Specify interface
sudo /full/path/to/venv/python scanner.py 192.168.1.0/24 --iface eth0 --tcp-ports 22-25
```

### Troubleshooting
- Root is required for ARP and TCP SYN scans, so use sudo.
- If you see `ModuleNotFoundError: No module named 'scapy'`, you probably ran the system Python instead of the venv Python. Use the venv interpreter path with sudo:
  - Verify install: `source .venv/bin/activate && python3 -c "import scapy, sys; print('scapy', scapy.__version__, 'python', sys.version)"`
  - Run with sudo using venv Python directly:
    `sudo "$(pwd)"/.venv/bin/python scanner.py 127.0.0.1/32 --no-arp --tcp-ports 80`
  - Or preserve env with python3:
    `source .venv/bin/activate && sudo -E "$(which python3)" scanner.py 127.0.0.1/32 --no-arp --tcp-ports 80`
- If `python` is missing or points to v2, always use `python3`.

### Quickstart
```bash
git clone <your-repo-url> network-scanner-scapy
cd network-scanner-scapy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Test CLI (no root needed)
python3 scanner.py --help

# Example scan (needs root)
sudo "$(pwd)"/.venv/bin/python scanner.py 192.168.1.0/24 --tcp-ports 22,80,443
```

### WSL Note
- I worked on WSL so I'd like to add that on WSL the commands above work the same. If scanning your LAN, ensure your WSL distro has access to your network interface and you run with `sudo`.

### Final Note
- If you prefer to not use venv it is uneccessary, just make sure everything is installed and defined properly in whatever enviroment you're using

### Legal and Ethical Notice
Only scan networks you own or have explicit permission to test.
