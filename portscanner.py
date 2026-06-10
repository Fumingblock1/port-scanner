#!/usr/bin/env python3
"""
portscanner.py — A fast, lightweight port scanner
Usage: python3 portscanner.py <host> [options]
"""

import socket
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Common service names ──────────────────────────────────────────────────────
COMMON_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP-submit", 631: "IPP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2181: "Zookeeper", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    6443: "Kubernetes", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "Jupyter", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
}

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def color(text, code):
    return f"{code}{text}{RESET}"


def banner():
    art = r"""
  ____            _     ____
 |  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
 | |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |
 |_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|
"""
    print(color(art, CYAN))
    print(color("  Fast TCP Port Scanner  ·  Use responsibly on systems you own\n", DIM))


def resolve_host(host: str) -> str:
    """Resolve hostname to IP, exit if unreachable."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(color(f"[!] Cannot resolve host: {host}", RED))
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Attempt to grab a service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send a generic probe for HTTP-like services
            if port in (80, 8080, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            else:
                s.sendall(b"\r\n")
            data = s.recv(256)
            return data.decode(errors="replace").strip().split("\n")[0][:80]
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict | None:
    """
    Returns a dict if the port is open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "unknown")
                banner = grab_banner(ip, port, timeout) if grab else ""
                return {"port": port, "service": service, "banner": banner}
    except Exception:
        pass
    return None


def parse_ports(port_str: str) -> list[int]:
    """
    Parse port specification:
      - "top"       → top 1000 common ports
      - "all"       → 1–65535
      - "80"        → single port
      - "20-25"     → range
      - "22,80,443" → list
    """
    if port_str == "all":
        return list(range(1, 65536))
    if port_str == "top":
        # Top ~1000 ports (well-known + registered)
        return list(range(1, 1025)) + sorted(COMMON_SERVICES.keys())
    if port_str == "common":
        return sorted(COMMON_SERVICES.keys())

    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def run_scan(args):
    banner()
    host = args.host
    ip   = resolve_host(host)
    ports = parse_ports(args.ports)

    label = "common" if args.ports == "common" else \
            "top"    if args.ports == "top"    else \
            "all"    if args.ports == "all"    else args.ports

    print(f"  {color('Target :', BOLD)} {host} ({color(ip, YELLOW)})")
    print(f"  {color('Ports  :', BOLD)} {label} ({len(ports)} ports)")
    print(f"  {color('Threads:', BOLD)} {args.threads}")
    print(f"  {color('Timeout:', BOLD)} {args.timeout}s")
    print(f"  {color('Banners:', BOLD)} {'yes' if args.banners else 'no'}")
    print(f"  {color('Started:', BOLD)} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print("  " + "─" * 62)

    open_ports = []
    start = time.time()
    scanned = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, p, args.timeout, args.banners): p
            for p in ports
        }
        for future in as_completed(futures):
            scanned += 1
            result = future.result()
            if result:
                open_ports.append(result)
                port    = result["port"]
                service = result["service"]
                banner_txt = f"  {color(result['banner'], DIM)}" if result["banner"] else ""
                print(f"  {color('OPEN', GREEN)}  {color(str(port).ljust(6), BOLD)}  {service.ljust(18)}{banner_txt}")

    elapsed = time.time() - start
    open_ports.sort(key=lambda x: x["port"])

    print("  " + "─" * 62)
    print(f"\n  Scanned {scanned} ports in {elapsed:.2f}s  ·  "
          f"{color(str(len(open_ports)) + ' open', GREEN if open_ports else RED)}\n")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"# Port scan: {host} ({ip})  —  {datetime.now()}\n")
            f.write(f"# Ports: {label}  Threads: {args.threads}\n\n")
            f.write(f"{'PORT':<8}{'SERVICE':<20}BANNER\n")
            f.write("─" * 60 + "\n")
            for r in open_ports:
                f.write(f"{r['port']:<8}{r['service']:<20}{r['banner']}\n")
        print(f"  Results saved to {color(args.output, CYAN)}\n")


def main():
    parser = argparse.ArgumentParser(
        description="portscanner.py — Fast TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 portscanner.py scanme.nmap.org
  python3 portscanner.py 192.168.1.1 -p 22,80,443
  python3 portscanner.py 10.0.0.1 -p 1-1024 -t 200 --banners
  python3 portscanner.py example.com -p common --output results.txt

Port presets:
  common   ~60 well-known services (fastest)
  top      ports 1-1024 + common services
  all      1-65535 (slow — use with high --threads)
        """
    )
    parser.add_argument("host",          help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="common",
                        help="Ports: 'common' | 'top' | 'all' | '80' | '20-25' | '22,80,443'  (default: common)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Concurrent threads (default: 100)")
    parser.add_argument("--timeout",     type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--banners",     action="store_true",
                        help="Attempt to grab service banners")
    parser.add_argument("--output",      metavar="FILE",
                        help="Save results to a text file")
    args = parser.parse_args()
    run_scan(args)


if __name__ == "__main__":
    main()
