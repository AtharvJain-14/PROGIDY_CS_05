#!/usr/bin/env python3
"""
=============================================================
  PacketScope — Educational Network Packet Sniffer
  Author : Educational Demo
  License: MIT (Educational Use Only)
=============================================================

⚠️  ETHICAL NOTICE
  This tool is intended strictly for:
    • Learning about TCP/IP networking
    • Analysing traffic on networks YOU own or have
      explicit written permission to monitor
    • Lab / CTF / classroom environments

  Unauthorized interception of network traffic is
  illegal in most jurisdictions (CFAA, GDPR, etc.).
  The author accepts NO liability for misuse.
=============================================================
"""

import argparse
import csv
import datetime
import json
import os
import signal
import sys
import textwrap
import time
from collections import defaultdict

# ── dependency check ────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
        ARP, DNS, DNSQR, DNSRR, Raw, Ether, conf, get_if_list
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    sys.exit(
        "\n[ERROR] Scapy is not installed.\n"
        "Install it with:  pip install scapy\n"
    )

# ── ANSI colours (disabled automatically on Windows / no-tty) ─
USE_COLOR = sys.stdout.isatty() and os.name != "nt"

class C:
    RESET  = "\033[0m"   if USE_COLOR else ""
    BOLD   = "\033[1m"   if USE_COLOR else ""
    RED    = "\033[91m"  if USE_COLOR else ""
    GREEN  = "\033[92m"  if USE_COLOR else ""
    YELLOW = "\033[93m"  if USE_COLOR else ""
    CYAN   = "\033[96m"  if USE_COLOR else ""
    MAGENTA= "\033[95m"  if USE_COLOR else ""
    BLUE   = "\033[94m"  if USE_COLOR else ""
    DIM    = "\033[2m"   if USE_COLOR else ""

# ── protocol name helpers ────────────────────────────────────
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP",  53: "DNS",  67: "DHCP", 68: "DHCP",
    80: "HTTP",  110: "POP3",143: "IMAP",443: "HTTPS",
    465: "SMTPS",587: "SMTP",993: "IMAPS",995:"POP3S",
    3306:"MySQL",5432:"PostgreSQL",6379:"Redis",
    27017:"MongoDB",8080:"HTTP-ALT",8443:"HTTPS-ALT",
}

def port_service(port: int) -> str:
    return WELL_KNOWN_PORTS.get(port, str(port))

def proto_color(proto: str) -> str:
    mapping = {
        "TCP": C.GREEN, "UDP": C.CYAN, "ICMP": C.YELLOW,
        "ARP": C.MAGENTA, "DNS": C.BLUE, "HTTP": C.RED,
        "HTTPS": C.RED, "IPv6": C.DIM,
    }
    return mapping.get(proto, C.RESET)

# ── statistics tracker ───────────────────────────────────────
class Stats:
    def __init__(self):
        self.total      = 0
        self.by_proto   = defaultdict(int)
        self.by_src_ip  = defaultdict(int)
        self.by_dst_ip  = defaultdict(int)
        self.bytes_seen = 0
        self.start_time = time.time()

    def record(self, proto, src, dst, size):
        self.total       += 1
        self.bytes_seen  += size
        self.by_proto[proto]  += 1
        self.by_src_ip[src]   += 1
        self.by_dst_ip[dst]   += 1

    def summary(self) -> str:
        elapsed = time.time() - self.start_time
        lines = [
            f"\n{C.BOLD}{'='*58}{C.RESET}",
            f"{C.BOLD}  SESSION SUMMARY{C.RESET}",
            f"{'='*58}",
            f"  Duration       : {elapsed:.1f}s",
            f"  Packets        : {self.total}",
            f"  Bytes captured : {self.bytes_seen:,}",
            f"  Avg rate       : {self.total/max(elapsed,1):.1f} pkt/s",
            "",
            f"  {C.BOLD}Protocol breakdown:{C.RESET}",
        ]
        for p, n in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            bar = "█" * min(30, int(30 * n / max(self.total, 1)))
            lines.append(f"    {p:<10} {bar} {n}")
        lines.append("")
        lines.append(f"  {C.BOLD}Top 5 source IPs:{C.RESET}")
        for ip, n in sorted(self.by_src_ip.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"    {ip:<20} {n} packets")
        lines.append(f"{'='*58}\n")
        return "\n".join(lines)

# ── payload formatter ────────────────────────────────────────
def format_payload(data: bytes, max_bytes: int = 128) -> str:
    snippet = data[:max_bytes]
    hex_part  = " ".join(f"{b:02x}" for b in snippet)
    try:
        text_part = snippet.decode("utf-8", errors="replace")
        text_part = "".join(c if c.isprintable() else "." for c in text_part)
    except Exception:
        text_part = "."*len(snippet)
    truncated = " …" if len(data) > max_bytes else ""
    return (
        f"\n      {C.DIM}HEX : {hex_part}{truncated}{C.RESET}"
        f"\n      {C.DIM}TXT : {text_part}{truncated}{C.RESET}"
    )

# ── packet record (for export) ───────────────────────────────
packet_log: list[dict] = []

# ── core callback ────────────────────────────────────────────
def process_packet(pkt, *, stats: Stats, args: argparse.Namespace):
    ts   = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    size = len(pkt)

    # ── Determine addresses & protocol ──────────────────────
    src_ip = dst_ip = proto = "?"
    src_port = dst_port = None
    flags = ""
    extra_info = ""

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            proto    = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            f        = pkt[TCP].flags
            flag_map = {0x02:"SYN",0x10:"ACK",0x01:"FIN",
                        0x04:"RST",0x18:"PSH+ACK",0x12:"SYN+ACK"}
            flags = flag_map.get(int(f), str(f))

            # HTTP layer detection
            if HTTPRequest in pkt:
                proto = "HTTP"
                method = pkt[HTTPRequest].Method.decode(errors="replace")
                path   = pkt[HTTPRequest].Path.decode(errors="replace")
                host   = (pkt[HTTPRequest].Host or b"").decode(errors="replace")
                extra_info = f"  {C.RED}► {method} {host}{path}{C.RESET}"
            elif HTTPResponse in pkt:
                proto  = "HTTP"
                status = pkt[HTTPResponse].Status_Code.decode(errors="replace")
                extra_info = f"  {C.RED}◄ HTTP {status}{C.RESET}"
            elif dst_port == 443 or src_port == 443:
                proto = "HTTPS"

        elif UDP in pkt:
            proto    = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            if DNS in pkt:
                proto = "DNS"
                dns   = pkt[DNS]
                if dns.qr == 0 and DNSQR in dns:          # query
                    qname = dns[DNSQR].qname.decode(errors="replace").rstrip(".")
                    extra_info = f"  {C.BLUE}? {qname}{C.RESET}"
                elif dns.qr == 1 and DNSRR in dns:         # response
                    ans = dns[DNSRR]
                    extra_info = f"  {C.BLUE}✓ {ans.rrname.decode(errors='replace').rstrip('.')} → {ans.rdata}{C.RESET}"

        elif ICMP in pkt:
            proto = "ICMP"
            itype = pkt[ICMP].type
            icode = pkt[ICMP].code
            names = {0:"Echo Reply",8:"Echo Request",3:"Unreachable",
                     11:"Time Exceeded",5:"Redirect"}
            extra_info = f"  {C.YELLOW}type={names.get(itype,itype)} code={icode}{C.RESET}"

    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        proto  = "IPv6"

    elif ARP in pkt:
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        proto  = "ARP"
        op     = "REQUEST" if pkt[ARP].op == 1 else "REPLY"
        extra_info = f"  {C.MAGENTA}{op} who-has {dst_ip} tell {src_ip}{C.RESET}"

    # ── apply BPF / keyword filter ───────────────────────────
    if args.filter_proto and proto.upper() != args.filter_proto.upper():
        return
    if args.filter_ip and args.filter_ip not in (src_ip, dst_ip):
        return
    if args.filter_port and src_port != args.filter_port and dst_port != args.filter_port:
        return

    # ── update stats ─────────────────────────────────────────
    stats.record(proto, src_ip, dst_ip, size)

    # ── build port string ────────────────────────────────────
    port_str = ""
    if src_port is not None:
        port_str = (f":{C.DIM}{port_service(src_port)}{C.RESET}"
                    f" → :{C.DIM}{port_service(dst_port)}{C.RESET}")

    # ── colour-code protocol ─────────────────────────────────
    pc = proto_color(proto)
    flag_str = f" [{flags}]" if flags else ""

    # ── print one-liner ──────────────────────────────────────
    print(
        f"{C.DIM}{ts}{C.RESET}  "
        f"{pc}{C.BOLD}{proto:<7}{C.RESET}"
        f"  {src_ip:<18} → {dst_ip:<18}"
        f"{port_str}{flag_str}"
        f"  {C.DIM}{size:>5}B{C.RESET}"
        f"{extra_info}"
    )

    # ── optional payload dump ────────────────────────────────
    if args.show_payload and Raw in pkt:
        print(format_payload(bytes(pkt[Raw])))

    # ── optional verbose Scapy summary ───────────────────────
    if args.verbose:
        print(f"      {C.DIM}{pkt.summary()}{C.RESET}")

    # ── save to in-memory log for export ────────────────────
    record = {
        "timestamp" : ts,
        "protocol"  : proto,
        "src_ip"    : src_ip,
        "dst_ip"    : dst_ip,
        "src_port"  : src_port,
        "dst_port"  : dst_port,
        "flags"     : flags,
        "size_bytes": size,
    }
    if args.save:
        packet_log.append(record)

# ── export helpers ────────────────────────────────────────────
def save_json(path: str):
    with open(path, "w") as f:
        json.dump(packet_log, f, indent=2)
    print(f"{C.GREEN}[✓] Saved {len(packet_log)} records → {path}{C.RESET}")

def save_csv(path: str):
    if not packet_log:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=packet_log[0].keys())
        w.writeheader()
        w.writerows(packet_log)
    print(f"{C.GREEN}[✓] Saved {len(packet_log)} records → {path}{C.RESET}")

# ── banner ────────────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
  ██████╔╝███████║██║     █████╔╝ █████╗     ██║   
  ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   
  ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝  
  ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ███████╗██║     ██║   ██║██████╔╝█████╗  
  ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
  ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
{C.RESET}
  {C.YELLOW}⚠  For authorised networks and educational use only  ⚠{C.RESET}
"""

# ── argument parser ───────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            PacketScope – lightweight educational packet sniffer
            Capture, display and optionally save network packets.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              sudo python sniffer.py                          # capture everything
              sudo python sniffer.py -i eth0 -n 50           # 50 packets on eth0
              sudo python sniffer.py -f tcp -p               # TCP only + payloads
              sudo python sniffer.py --filter-ip 8.8.8.8     # filter by IP
              sudo python sniffer.py --bpf "port 443"        # raw BPF filter
              sudo python sniffer.py -s capture.json         # save to JSON
              sudo python sniffer.py -s capture.csv          # save to CSV
        """),
    )
    p.add_argument("-i", "--iface",       metavar="IFACE",
                   help="Network interface (default: auto-select)")
    p.add_argument("-n", "--count",       type=int, default=0,  metavar="N",
                   help="Stop after N packets (0 = unlimited)")
    p.add_argument("-f", "--filter-proto",metavar="PROTO",
                   help="Show only this protocol: TCP|UDP|ICMP|DNS|ARP|HTTP|HTTPS")
    p.add_argument("--filter-ip",         metavar="IP",
                   help="Show only packets involving this IP address")
    p.add_argument("--filter-port",       type=int, metavar="PORT",
                   help="Show only packets involving this port number")
    p.add_argument("--bpf",               metavar="EXPR",
                   help='Raw BPF filter expression, e.g. "tcp port 80"')
    p.add_argument("-p", "--show-payload", action="store_true",
                   help="Print raw payload (hex + printable ASCII)")
    p.add_argument("-v", "--verbose",      action="store_true",
                   help="Print full Scapy packet summary per packet")
    p.add_argument("-s", "--save",         metavar="FILE",
                   help="Save captured packets to FILE (.json or .csv)")
    p.add_argument("--list-ifaces",        action="store_true",
                   help="Print available network interfaces and exit")
    return p

# ── main ──────────────────────────────────────────────────────
def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.list_ifaces:
        print(f"\n{C.BOLD}Available interfaces:{C.RESET}")
        for iface in get_if_list():
            print(f"  • {iface}")
        print()
        sys.exit(0)

    print(BANNER)

    # ── confirm ethical use ──────────────────────────────────
    print(f"{C.YELLOW}By using PacketScope you confirm that:{C.RESET}")
    print("  [1] You own or have explicit permission to monitor this network.")
    print("  [2] You will not capture credentials or private data without consent.")
    print("  [3] You understand that unauthorised sniffing may be illegal.\n")
    try:
        answer = input(f"{C.BOLD}Proceed? (yes/no): {C.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        sys.exit(0)
    if answer not in ("yes", "y"):
        print("Aborted.")
        sys.exit(0)

    stats = Stats()

    # ── graceful Ctrl-C ──────────────────────────────────────
    def on_interrupt(*_):
        print(stats.summary())
        if args.save:
            ext = os.path.splitext(args.save)[1].lower()
            if ext == ".csv":
                save_csv(args.save)
            else:
                save_json(args.save if ext == ".json" else args.save + ".json")
        sys.exit(0)

    signal.signal(signal.SIGINT,  on_interrupt)
    signal.signal(signal.SIGTERM, on_interrupt)

    # ── header row ───────────────────────────────────────────
    print(
        f"\n{C.BOLD}"
        f"{'TIME':<14}{'PROTO':<9}{'SRC IP':<20}  {'DST IP':<20}"
        f"{'PORTS':<25}{'SIZE'}"
        f"{C.RESET}"
    )
    print("─" * 100)

    iface    = args.iface or None
    bpf_expr = args.bpf  or None
    count    = args.count or 0

    conf.verb = 0   # silence Scapy's own output

    try:
        sniff(
            iface  = iface,
            filter = bpf_expr,
            count  = count,
            prn    = lambda pkt: process_packet(pkt, stats=stats, args=args),
            store  = False,
        )
    except RuntimeError as e:
        if "layer 2" in str(e).lower() or "winpcap" in str(e).lower():
            print(f"\n{C.RED}[ERROR]{C.RESET} Npcap/WinPcap is required for packet capture on Windows.")
            print(f"Please download and install Npcap from: {C.CYAN}https://npcap.com/#download{C.RESET}\n")
            sys.exit(1)
        else:
            raise

    # reached if count > 0
    on_interrupt()

if __name__ == "__main__":
    main()
