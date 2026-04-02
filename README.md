# 🔭 PacketScope — Educational Network Packet Sniffer

> **A lightweight, terminal-based packet sniffer built with Python & Scapy.**
> Designed for learning TCP/IP networking, protocol analysis, and network forensics in controlled, authorised environments.

---

## ⚠️ Ethical & Legal Disclaimer

> **READ THIS BEFORE USING THE TOOL.**

Capturing network traffic without explicit authorisation is **illegal** in most countries, including under:

| Jurisdiction | Law |
|---|---|
| United States | Computer Fraud and Abuse Act (CFAA), Wiretap Act |
| European Union | General Data Protection Regulation (GDPR), Directive 2013/40/EU |
| United Kingdom | Computer Misuse Act 1990, RIPA 2000 |
| India | IT Act 2000, Section 43 & 66 |

**Authorised use ONLY:**
- Your own home or lab network
- Corporate/enterprise networks with **written permission** from the network owner
- Virtual lab environments (GNS3, EVE-NG, VirtualBox host-only networks)
- CTF (Capture The Flag) competition environments
- Academic coursework with instructor approval

The author and contributors accept **zero liability** for any misuse.

---

## 🌟 Features

| Feature | Description |
|---|---|
| **Multi-protocol support** | TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, IPv6 |
| **Colour-coded output** | Each protocol rendered in a distinct colour for quick scanning |
| **Payload inspection** | Optional hex + ASCII dump of raw packet payload |
| **HTTP layer decoding** | Extracts method, host, path from HTTP requests; status from responses |
| **DNS decoding** | Shows queried hostnames and resolved IP addresses |
| **ICMP analysis** | Displays type/code with human-readable names |
| **ARP decoding** | Shows who-has/tell requests and replies |
| **Flexible filtering** | By protocol, IP address, port number, or raw BPF expression |
| **Live statistics** | Protocol breakdown, top talkers, bytes captured, packet rate |
| **Export support** | Save captures to JSON or CSV for offline analysis |
| **Graceful shutdown** | Ctrl-C prints a full session summary before exit |

---

## 🖥️ Requirements

| Requirement | Detail |
|---|---|
| Python | 3.9 or newer |
| Scapy | ≥ 2.5.0 |
| OS | Linux, macOS, Windows (WSL2 recommended on Windows) |
| Privileges | **Root / Administrator** required for raw socket access |

---

## 📦 Installation

### 1 — Clone or download

```bash
git clone https://github.com/your-repo/packetscope.git
cd packetscope
```

### 2 — Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### 4 — Verify Scapy installation

```bash
python -c "from scapy.all import sniff; print('Scapy OK')"
```

---

## 🚀 Quick Start

```bash
# Linux / macOS — root is required
sudo python sniffer.py

# Windows (run terminal as Administrator)
python sniffer.py
```

You will be prompted to confirm ethical use before any packets are captured.

---

## 📖 Usage

```
usage: sniffer.py [-h] [-i IFACE] [-n N] [-f PROTO] [--filter-ip IP]
                  [--filter-port PORT] [--bpf EXPR] [-p] [-v] [-s FILE]
                  [--list-ifaces]
```

### Options

| Flag | Long form | Description |
|---|---|---|
| `-h` | `--help` | Show help and exit |
| `-i IFACE` | `--iface IFACE` | Network interface to listen on (default: auto) |
| `-n N` | `--count N` | Stop after N packets (0 = unlimited) |
| `-f PROTO` | `--filter-proto` | Show only: `TCP` `UDP` `ICMP` `DNS` `ARP` `HTTP` `HTTPS` |
| | `--filter-ip IP` | Show only packets involving this IP |
| | `--filter-port PORT` | Show only packets involving this port |
| | `--bpf EXPR` | Raw BPF filter string passed directly to libpcap |
| `-p` | `--show-payload` | Print hex + ASCII payload dump |
| `-v` | `--verbose` | Print full Scapy packet summary |
| `-s FILE` | `--save FILE` | Save to FILE (`.json` or `.csv`) |
| | `--list-ifaces` | List available interfaces and exit |

---

## 💡 Examples

### List available interfaces
```bash
sudo python sniffer.py --list-ifaces
```

### Capture 100 packets on `eth0`
```bash
sudo python sniffer.py -i eth0 -n 100
```

### Show only DNS traffic
```bash
sudo python sniffer.py -f dns
```

### Filter by IP address
```bash
sudo python sniffer.py --filter-ip 192.168.1.1
```

### Filter by port
```bash
sudo python sniffer.py --filter-port 443
```

### Use a raw BPF filter
```bash
sudo python sniffer.py --bpf "tcp port 80 or tcp port 443"
```

### Show payload + verbose output
```bash
sudo python sniffer.py -p -v -f http
```

### Save 200 packets to JSON
```bash
sudo python sniffer.py -n 200 -s capture.json
```

### Save to CSV
```bash
sudo python sniffer.py -n 200 -s capture.csv
```

---

## 📊 Output Format

### One-liner per packet

```
TIME          PROTO    SRC IP               DST IP               PORTS                 SIZE
──────────────────────────────────────────────────────────────────────────────────────────────
09:14:22.301  DNS      192.168.1.10         8.8.8.8              :49231 → :DNS          72B   ? github.com
09:14:22.410  DNS      8.8.8.8              192.168.1.10         :DNS → :49231          88B   ✓ github.com → 140.82.121.4
09:14:22.450  TCP      192.168.1.10         140.82.121.4         :52301 → :HTTPS       66B  [SYN]
09:14:22.490  TCP      140.82.121.4         192.168.1.10         :HTTPS → :52301       66B  [SYN+ACK]
09:14:23.100  HTTP     192.168.1.10         93.184.216.34        :54120 → :HTTP        421B  ► GET example.com/index.html
09:14:24.200  ARP      192.168.1.1          192.168.1.10                               42B   REQUEST who-has 192.168.1.10 tell 192.168.1.1
09:14:25.300  ICMP     192.168.1.10         8.8.8.8                                    84B   type=Echo Request code=0
```

### Payload dump (with `-p`)

```
      HEX : 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a …
      TXT : GET / HTTP/1.1..Host: example.com..User-Agent: …
```

### Session summary (on Ctrl-C)

```
==========================================================
  SESSION SUMMARY
==========================================================
  Duration       : 42.3s
  Packets        : 187
  Bytes captured : 134,291
  Avg rate       : 4.4 pkt/s

  Protocol breakdown:
    TCP        ████████████████████ 91
    DNS        ████████ 38
    HTTPS      ██████ 27
    UDP        ████ 18
    ARP        ██ 9
    ICMP       █ 4

  Top 5 source IPs:
    192.168.1.10         91 packets
    8.8.8.8              38 packets
    140.82.121.4         27 packets
==========================================================
```

---

## 🗂️ Export Formats

### JSON (`-s capture.json`)
```json
[
  {
    "timestamp": "09:14:22.301",
    "protocol": "DNS",
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "src_port": 49231,
    "dst_port": 53,
    "flags": "",
    "size_bytes": 72
  },
  ...
]
```

### CSV (`-s capture.csv`)
```
timestamp,protocol,src_ip,dst_ip,src_port,dst_port,flags,size_bytes
09:14:22.301,DNS,192.168.1.10,8.8.8.8,49231,53,,72
```

JSON exports can be imported into tools like **Wireshark** (via tshark JSON import), **Jupyter Notebooks**, **Elasticsearch**, or **Splunk** for further analysis.

---

## 🧩 Supported Protocols — Deep Dive

### TCP
Captures all TCP segments. Flags decoded: `SYN`, `ACK`, `FIN`, `RST`, `PSH+ACK`, `SYN+ACK`.

### UDP
Generic UDP datagrams with port resolution.

### DNS
Distinguishes queries (marked `?`) from responses (marked `✓`). Displays queried hostname and resolved address.

### HTTP
Leverages Scapy's HTTP layer to extract:
- **Requests** → method, host, path
- **Responses** → status code

### HTTPS
Identified by port 443; payload content is encrypted and not decoded (by design — this is correct behaviour).

### ICMP
Type and code decoded with human-readable names (Echo Request, Echo Reply, Unreachable, Time Exceeded, Redirect).

### ARP
Displays operation (REQUEST/REPLY), target IP, and sender IP — useful for detecting ARP cache poisoning.

### IPv6
Basic source/destination display for IPv6 traffic.

---

## 🔬 Educational Lab Exercises

### Exercise 1 — DNS Resolution
```bash
sudo python sniffer.py -f dns -n 20
```
Open a browser and visit a few new websites. Watch how DNS queries resolve hostnames to IPs in real time.

### Exercise 2 — TCP Three-Way Handshake
```bash
sudo python sniffer.py -f tcp --filter-port 80 -n 10
```
Visit an HTTP site. Identify the `SYN → SYN+ACK → ACK` sequence that establishes a TCP connection.

### Exercise 3 — ARP Table Observation
```bash
sudo python sniffer.py -f arp
```
Run `ping 192.168.1.1` in another terminal. Observe the ARP REQUEST/REPLY exchange that discovers the MAC address.

### Exercise 4 — HTTP Header Inspection
```bash
sudo python sniffer.py -f http -p
```
Visit a plain HTTP page (not HTTPS). Inspect the headers and path in the payload dump.

### Exercise 5 — Full Capture to CSV
```bash
sudo python sniffer.py -n 500 -s session.csv
```
Open `session.csv` in Excel or a Jupyter Notebook and graph packet counts by protocol.

---

## 🏗️ Project Structure

```
packetscope/
├── sniffer.py          # Main sniffer script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 🔧 Troubleshooting

| Problem | Solution |
|---|---|
| `Permission denied` | Run with `sudo` (Linux/macOS) or as Administrator (Windows) |
| `No module named scapy` | Run `pip install scapy` in your active environment |
| No packets captured | Check `-i` interface name; run `--list-ifaces` to find it |
| `OSError: [Errno 1] Operation not permitted` | Root/admin privileges required for raw sockets |
| Windows: no capture | Install [Npcap](https://npcap.com/) (not WinPcap) |
| macOS: interface name | Use `en0` for Wi-Fi, `en1` for Ethernet, `lo0` for loopback |

---

## 🗺️ Roadmap / Possible Enhancements

- [ ] GeoIP lookup for external IPs
- [ ] Real-time bandwidth graph (curses/rich TUI)
- [ ] PCAP export (`.pcap` readable by Wireshark)
- [ ] TLS/SSL SNI extraction (without decryption)
- [ ] Port scan detection heuristic
- [ ] Anomaly alerting (high rate from single host)
- [ ] Docker container for isolated lab use

---

## 📚 Further Reading

- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [Scapy Official Documentation](https://scapy.readthedocs.io/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [TCP/IP Illustrated, Vol. 1 — W. Richard Stevens](https://www.informit.com/store/tcp-ip-illustrated-volume-1-the-protocols-9780321336316)
- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)

---

## 📄 License

MIT License — see `LICENSE` file. Free for educational and personal use.
Use responsibly. The authors are not responsible for any misuse.

---

*PacketScope — Know your network.*
