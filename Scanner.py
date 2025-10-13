
#!/usr/bin/env python3
import argparse
import ipaddress
import sys
from typing import List, Tuple


def lazy_import_scapy():
	# Import Scapy only when needed so --help works without dependencies installed
	from importlib import import_module
	return import_module("scapy.all")


def parse_ports(ports_arg: str) -> List[int]:
	ports: List[int] = []
	for token in ports_arg.split(","):
		token = token.strip()
		if not token:
			continue
		if "-" in token:
			start_str, end_str = token.split("-", 1)
			start = int(start_str)
			end = int(end_str)
			if start > end:
				start, end = end, start
			ports.extend(range(start, end + 1))
		else:
			ports.append(int(token))
	return sorted(set(p for p in ports if 1 <= p <= 65535))


def arp_sweep(cidr: str, iface: str | None, timeout: float) -> List[Tuple[str, str]]:
	scapy = lazy_import_scapy()
	ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp = scapy.ARP(pdst=cidr)
	packet = ether / arp
	answered, _ = scapy.srp(packet, timeout=timeout, iface=iface, verbose=False)
	results: List[Tuple[str, str]] = []
	for snd, rcv in answered:
		results.append((rcv.psrc, rcv.hwsrc))
	return results


def tcp_syn_scan(host: str, ports: List[int], iface: str | None, timeout: float) -> List[int]:
	scapy = lazy_import_scapy()
	open_ports: List[int] = []
	for port in ports:
		pkt = scapy.IP(dst=host) / scapy.TCP(dport=port, flags="S")
		resp = scapy.sr1(pkt, timeout=timeout, iface=iface, verbose=False)
		if resp is None:
			continue
		if resp.haslayer(scapy.TCP):
			flags = resp.getlayer(scapy.TCP).flags
			# SYN+ACK => open
			if flags & 0x12 == 0x12:
				open_ports.append(port)
				# Send RST to be polite
				scapy.send(scapy.IP(dst=host) / scapy.TCP(dport=port, flags="R"), verbose=False)
	return open_ports


def main(argv: List[str]) -> int:
	parser = argparse.ArgumentParser(
		description="Simple Scapy-based network scanner (ARP sweep + optional TCP SYN scan)",
	)
	parser.add_argument("target", help="Target CIDR, e.g. 192.168.1.0/24")
	parser.add_argument(
		"--iface",
		dest="iface",
		help="Network interface to use (optional)",
	)
	parser.add_argument(
		"--timeout",
		type=float,
		default=1.0,
		help="Timeout in seconds for ARP/TCP probes (default: 1.0)",
	)
	parser.add_argument(
		"--tcp-ports",
		help="Comma-separated list or ranges for TCP SYN scan (e.g., 22,80,443 or 1-1024)",
	)
	parser.add_argument(
		"--no-arp",
		action="store_true",
		help="Skip ARP sweep and only run TCP scan on all hosts in CIDR",
	)

	args = parser.parse_args(argv)

	# Validate target
	try:
		cidr = str(ipaddress.ip_network(args.target, strict=False))
	except ValueError as exc:
		print(f"Invalid target CIDR: {exc}")
		return 2

	iface = args.iface
	timeout = args.timeout
	ports: List[int] = []
	if args.tcp_ports:
		try:
			ports = parse_ports(args.tcp_ports)
		except Exception as exc:
			print(f"Invalid --tcp-ports value: {exc}")
			return 2

	print(f"[+] Scanning {cidr}")

	hosts: List[str] = []
	if not args.no_arp:
		print("[+] Running ARP sweep (requires sudo/root)...")
		try:
			alive = arp_sweep(cidr=cidr, iface=iface, timeout=timeout)
			if not alive:
				print("[!] No hosts responded to ARP")
			else:
				print("[+] Alive hosts:")
				for ip_addr, mac in alive:
					print(f"    {ip_addr}\t{mac}")
				hosts = [ip for ip, _ in alive]
		except PermissionError:
			print("[!] Permission denied. Try running with sudo.")
			return 1
		except Exception as exc:
			print(f"[!] ARP sweep error: {exc}")
			return 1
	else:
		# If ARP is skipped, scan the entire CIDR range
		net = ipaddress.ip_network(cidr, strict=False)
		hosts = [str(h) for h in net.hosts()]

	if ports:
		print(f"[+] TCP SYN scan on {len(hosts)} host(s), ports: {','.join(map(str, ports))}")
		for host in hosts:
			try:
				open_ports = tcp_syn_scan(host=host, ports=ports, iface=iface, timeout=timeout)
				if open_ports:
					print(f"    {host}: open -> {','.join(map(str, open_ports))}")
				else:
					print(f"    {host}: no open ports found")
			except PermissionError:
				print("[!] Permission denied. Try running with sudo.")
				return 1
			except Exception as exc:
				print(f"[!] TCP scan error on {host}: {exc}")

	print("[+] Done")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))




