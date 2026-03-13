#!/usr/bin/python3
import random, socket, ssl, argparse, logging, json, time, signal, sys, csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, to_dict
DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,3306,6379,8080,8443"
BANNER_READ_BYTES = 4096
SCHEMA_VERSION = "1.1"
def configure_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
class ScanResult:
    __slots__ = (
        "host", "port", "reachable", "duration_s", "banner",
        "http", "tls", "certificate", "notes", "errors"
    )
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.reachable = False
        self.duration_s = 0.0
        self.banner = ""
        self.http: Dict[str, str] = {}
        self.tls: Dict[str, str] = {}
        self.certificate: Dict[str, str] = {}
        self.notes: List[str] = []
        self.errors: List[str] = []

    def to_dict(self):
        return {
            "host": self.host,
            "port": self.port,
            "reachable": bool(self.reachable),
            "duration_s": float(round(self.duration_s, 4)),
            "banner": self.banner or "",
            "http": self.http or {},
            "tls": self.tls or {},
            "certificate": self.certificate or {},
            "notes": list(self.notes),
            "errors": list(self.errors),
        }

def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if p < 1 or p > 65535:
            raise ValueError(f"Invalid port: {p}")
    return sorted(ports)

def recv_all(sock, timeout: float, max_bytes: int):
    sock.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while total < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    except socket.timeout:
        logging.warning("Socket read timed out.")
    except Exception as e:
        logging.error(f"Error receiving data: {e}")
    return b"".join(chunks).decode(errors="ignore")

def parse_http_response(data: str, result: ScanResult):
    lines = data.split("\r\n")
    if not lines:
        return
    status_line = lines[0]
    result.http["status_line"] = status_line
    parts = status_line.split(" ", 2)
    if len(parts) >= 2:
        result.http["status_code"] = parts[1]
        if len(parts) == 3:
            result.http["reason"] = parts[2]
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            result.http[k.lower()] = v.strip()
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.96 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.6 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/116.0.1938.69 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.96 Safari/537.36 OPR/102.0.4880.77",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230805.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.96 Mobile Safari/537.36",
    "Mozilla/5.0 (Android 13; Mobile; rv:118.0) Gecko/118.0 Firefox/118.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230805.001) AppleWebKit/537.36 (KHTML, like Gecko) Edg/116.0.1938.69 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230805.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.96 Mobile Safari/537.36 OPR/102.0.4880.77"
]
def rdmUA():
    return random.choice(user_agents)
def starttls_upgrade(sock, host, timeout, insecure, result):
    try:
        inspect_tls(sock, host, timeout, insecure, result)
        result.notes.append("STARTTLS successful")
    except Exception as e:
        result.errors.append(f"STARTTLS failed: {e}")

def inspect_tls(sock, host: str, timeout: float, insecure: bool, result: ScanResult):
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with context.wrap_socket(sock, server_hostname=host) as tls_sock:
        tls_sock.settimeout(timeout)
        tls_sock.do_handshake()

        result.tls["version"] = tls_sock.version()
        cipher = tls_sock.cipher()
        if cipher:
            result.tls["cipher_suite"] = cipher[0]
            result.tls["cipher_protocol"] = cipher[1]
            result.tls["cipher_bits"] = str(cipher[2])

        cert = tls_sock.getpeercert()
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            result.certificate["subject_cn"] = subject.get("commonName", "")
            result.certificate["issuer_cn"] = issuer.get("commonName", "")
            result.certificate["not_before"] = cert.get("notBefore", "")
            result.certificate["not_after"] = cert.get("notAfter", "")

def probe(host: str, port: int, timeout: float, insecure: bool) -> ScanResult:
    result = ScanResult(host, port)
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result.reachable = True
    except Exception as e:
        result.errors.append(str(e))
        result.duration_s = time.time() - start
        return result
    try:
        banner = recv_all(sock, timeout, BANNER_READ_BYTES)
        result.banner = banner
        if port == 25 and banner.startswith("220"):
            sock.sendall(b"EHLO scanner\r\n")
            if "STARTTLS" in recv_all(sock, timeout, BANNER_READ_BYTES).upper():
                sock.sendall(b"STARTTLS\r\n")
                recv_all(sock, timeout, BANNER_READ_BYTES)
                starttls_upgrade(sock, host, timeout, insecure, result)
        elif port == 110 and banner.startswith("+OK"):
            sock.sendall(b"STLS\r\n")
            if recv_all(sock, timeout, BANNER_READ_BYTES).startswith("+OK"):
                starttls_upgrade(sock, host, timeout, insecure, result)
        elif port == 143 and "IMAP" in banner.upper():
            sock.sendall(b"a001 STARTTLS\r\n")
            if "OK" in recv_all(sock, timeout, BANNER_READ_BYTES).upper():
                starttls_upgrade(sock, host, timeout, insecure, result)
        elif port in (443, 8443):
            inspect_tls(sock, host, timeout, insecure, result)
        elif port in (80, 8080):
            sock.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {rdmUA()}\r\n\r\n".encode()
            )
            parse_http_response(recv_all(sock, timeout, BANNER_READ_BYTES), result)
    except Exception as e:
        result.errors.append(str(e))
    finally:
        try:
            sock.close()
        except Exception:
            pass
    result.duration_s = time.time() - start
    return result
def setup_signal_handler():
    def handler(sig, frame):
        logging.warning("Interrupted. Exiting.")
        sys.exit(1)
    signal.signal(signal.SIGINT, handler)
def read_hosts_file(path: str) -> List[str]:
    hosts = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.append(line)
    if not hosts:
        raise ValueError("Hosts file is empty")
    return hosts
def parse_args():
    parser = argparse.ArgumentParser(
        description="Threaded TCP banner and TLS metadata scanner"
    )
    parser.add_argument("host", nargs="?",
                        help="Target host (ignored if --hosts-file is used)")
    parser.add_argument("--hosts-file",
                        help="File containing list of target hosts (one per line)")
    parser.add_argument("--ports", default=DEFAULT_PORTS,
                        help="Ports (e.g. 80,443 or 1-1024)")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--json", help="Write output to JSON file")
    parser.add_argument("--csv", help="Write output to CSV file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification")
    return parser.parse_args()
def write_csv(path: str, results: List[ScanResult]):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "host",
            "port",
            "reachable",
            "duration_s",
            "banner",
            "http_status",
            "tls_version",
            "tls_cipher",
            "cert_subject_cn",
            "cert_issuer_cn",
            "cert_not_before",
            "cert_not_after",
            "errors",
        ])
        for r in results:
            writer.writerow([
                r.host,
                r.port,
                r.reachable,
                f"{r.duration_s:.2f}",
                r.banner.strip(),
                r.http.get("status_code", ""),
                r.tls.get("version", ""),
                r.tls.get("cipher_suite", ""),
                r.certificate.get("subject_cn", ""),
                r.certificate.get("issuer_cn", ""),
                r.certificate.get("not_before", ""),
                r.certificate.get("not_after", ""),
                "; ".join(r.errors),
            ])
def main():
    args = parse_args()
    configure_logging(args.verbose)
    setup_signal_handler()
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)
    if args.hosts_file:
        try:
            hosts = read_hosts_file(args.hosts_file)
        except Exception as e:
            logging.error(str(e))
            sys.exit(1)
    else:
        if not args.host:
            logging.error("You must specify a host or --hosts-file")
            sys.exit(1)
        hosts = [args.host]
    logging.info(f"Scanning {len(hosts)} host(s) on {len(ports)} ports")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(probe, host, port, args.timeout, args.insecure)
            for host in hosts
            for port in ports
        ]
        for f in as_completed(futures):
            results.append(f.result())
    results.sort(key=lambda r: (r.host, r.port))
    for r in results:
        if not r.reachable:
            print(f"[{r.host}:{r.port}] unreachable")
            continue
        print(f"[{r.host}:{r.port}] reachable ({r.duration_s:.2f}s)")
        if r.banner:
            print(r.banner.strip())
        if r.tls:
            for k, v in r.tls.items():
                print(f"  TLS {k}: {v}")
        if r.certificate:
            for k, v in r.certificate.items():
                print(f"  Cert {k}: {v}")
        if r.errors:
            for e in r.errors:
                print(f"  Error: {e}")
        print()
    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "schema_version": SCHEMA_VERSION,
                    "results": [r.to_dict() for r in results],
                },
                f,
                indent=2,
            )
        logging.info(f"Results written to {args.json}")
    if args.csv:
        write_csv(args.csv, results)
        logging.info(f"Results written to {args.csv}")
if __name__ == "__main__":
    main()
