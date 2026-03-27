#!/usr/bin/python3
import asyncio,re,ssl,json,csv,time,signal,sys,argparse
from dataclasses import dataclass, field, asdict
from typing import List, Dict
from datetime import datetime
DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,3306,3309,6379,8080,8443,5432,6379,27017,5984,2222,5000,9000,10000,25565"
SCHEMA_VERSION = "1.1"
DEFAULT_TIMEOUT = 3.0
DEFAULT_THREADS = 8
BANNER_READ_BYTES = 4096
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1)",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7)",
]
@dataclass
class ScanResult:
    host: str
    port: int
    reachable: bool = False
    duration_s: float = 0.0
    banner: str = ""
    http: Dict[str, str] = field(default_factory=dict)
    tls: Dict[str, str] = field(default_factory=dict)
    certificate: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
@dataclass
class ScannerConfig:
    hosts: List[str]
    ports: List[int]
    timeout: float
    threads: int
    json_out: str
    csv_out: str
    verbose: bool
    insecure: bool
    ports_str: str
FINGERPRINT_DB = [
    {
        "service": "ssh",
        "patterns": [r"^SSH-\d\.\d-(?P<version>[^\r\n]+)"],
        "note": "SSH service detected"
    },
    {
        "service": "ftp",
        "patterns": [r"ftp", r"220.*ftp"],
        "note": "FTP service detected"
    },
    {
        "service": "smtp",
        "patterns": [r"smtp", r"220.*mail"],
        "note": "SMTP service detected"
    },
    {
        "service": "http",
        "patterns": [r"^HTTP/\d\.\d"],
        "note": "HTTP service detected"
    },
    {
        "service": "nginx",
        "patterns": [r"server:\s*nginx/?(?P<version>[^\s]*)"],
        "note": "Nginx detected"
    },
    {
        "service": "apache",
        "patterns": [r"server:\s*apache/?(?P<version>[^\s]*)"],
        "note": "Apache detected"
    },
    {
        "service": "mysql",
        "patterns": [r"mysql", r"\x00\x00\x00\x0a(?P<version>[^\x00]+)"],
        "note": "MySQL detected"
    },
    {
        "service": "postgresql",
        "patterns": [r"postgresql"],
        "note": "PostgreSQL detected"
    },
    {
        "service": "redis",
        "patterns": [r"-ERR", r"\+PONG", r"redis"],
        "note": "Redis detected"
    },
    {
        "service": "mongodb",
        "patterns": [r"mongodb"],
        "note": "MongoDB detected"
    },
]
def fingerprint_with_db(data: str, result: ScanResult):
    text = data.lower()
    for fp in FINGERPRINT_DB:
        for pattern in fp["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                note = fp["note"]
                if note not in result.notes:
                    result.notes.append(note)
                if "version" in match.groupdict():
                    version = match.group("version")
                    if version:
                        result.notes.append(f"{fp['service']} version: {version.strip()}")
                break
async def recv_all(reader: asyncio.StreamReader, timeout: float, max_bytes: int) -> str:
    data = b""
    try:
        while len(data) < max_bytes:
            chunk = await asyncio.wait_for(reader.read(8192), timeout)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data[:max_bytes].decode(errors="ignore")
def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)
def fingerprint_banner(banner: str, result: ScanResult):
    b = banner.lower()
    fingerprints = {
        "ssh": "SSH service detected",
        "ftp": "FTP service detected",
        "smtp": "SMTP service detected",
        "mysql": "MySQL service detected",
        "postgres": "PostgreSQL service detected",
        "redis": "Redis service detected",
        "mongodb": "MongoDB service detected",
        "http": "HTTP-like service detected",
    }
    for key, note in fingerprints.items():
        if key in b:
            result.notes.append(note)
async def active_probe(reader, writer, port: int, result: ScanResult):
    try:
        if port == 6379:  # Redis
            writer.write(b"PING\r\n")
            await writer.drain()
            resp = await reader.read(100)
            if b"PONG" in resp:
                result.notes.append("Redis confirmed via PING")
        elif port == 25:
            writer.write(b"EHLO test\r\n")
            await writer.drain()
            resp = await reader.read(200)
            if b"SMTP" in resp:
                result.notes.append("SMTP confirmed via EHLO")
        elif port == 21:
            writer.write(b"FEAT\r\n")
            await writer.drain()
            resp = await reader.read(200)
            if b"211" in resp:
                result.notes.append("FTP features detected")
    except Exception:
        pass
class AsyncPortScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.threads)
    async def inspect_tls(self, host: str, port: int, result: ScanResult):
        try:
            context = ssl.create_default_context()
            if self.config.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=self.config.timeout
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                result.tls["version"] = ssl_obj.version()
                result.tls["cipher"] = str(ssl_obj.cipher())
                cert = ssl_obj.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result.certificate["subject_cn"] = subject.get("commonName", "")
                    result.certificate["issuer_cn"] = issuer.get("commonName", "")
                    result.certificate["not_before"] = cert.get("notBefore", "")
                    result.certificate["not_after"] = cert.get("notAfter", "")
                    try:
                        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.now(datetime.utc)
                        result.certificate["cert_expired"] = str(now > not_after).lower()
                        result.certificate["cert_not_yet_valid"] = str(now < not_before).lower()
                        subject_cn = result.certificate.get("subject_cn", "")
                        issuer_cn = result.certificate.get("issuer_cn", "")
                        result.certificate["cert_self_signed"] = str(subject_cn == issuer_cn).lower()
                        if result.certificate["cert_expired"] == "true":
                            result.notes.append("Expired TLS certificate")
                        if result.certificate["cert_self_signed"] == "true":
                            result.notes.append("Self-signed certificate")

                    except Exception:
                        pass
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            result.errors.append(f"TLS error: {e}")
    async def probe(self, host: str, port: int) -> ScanResult:
        async with self.semaphore:
            result = ScanResult(host=host, port=port)
            start = time.time()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.config.timeout)
                result.reachable = True
                result.duration_s = time.time() - start
                result.banner = (await recv_all(reader, self.config.timeout, BANNER_READ_BYTES)).strip()
                fingerprint_with_db(result.banner, result)
                service_map = {
                    21: "FTP",
                    22: "SSH",
                    25: "SMTP",
                    3306: "MySQL",
                    5432: "PostgreSQL",
                    6379: "Redis",
                    27017: "MongoDB",
                }
                if port in service_map and result.banner:
                    result.notes.append(f"{service_map[port]} server detected")
                if port in (80, 8080, 443, 8443):
                    request = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENTS[0]}\r\n\r\n"
                    try:
                        writer.write(request.encode())
                        await writer.drain()
                        resp = await recv_all(reader, self.config.timeout, BANNER_READ_BYTES)
                        lines = resp.split("\r\n")
                        if lines and lines[0].startswith("HTTP/"):
                            result.http["status_line"] = lines[0]
                            for line in lines[1:]:
                                if not line:
                                    break
                                if ":" in line:
                                    k, v = line.split(":", 1)
                                    key = k.strip()
                                    val = v.strip()
                                    result.http[key] = val

                                    lk = key.lower()
                                    if lk == "server":
                                        result.http["server"] = val
                                    elif lk == "x-powered-by":
                                        result.http["powered_by"] = val
                                    elif lk == "content-type":
                                        result.http["content_type"] = val
                            if "server" in result.http:
                                result.notes.append(f"Server: {result.http['server']}")
                            if "powered_by" in result.http:
                                result.notes.append(f"Powered by: {result.http['powered_by']}")
                            if "application/json" in result.http.get("content_type", ""):
                                result.notes.append("Possible API endpoint")
                            if "location" in result.http:
                                result.notes.append("Redirect detected")
                            result.notes.append("HTTP server detected")
                    except Exception as e:
                        result.notes.append(f"HTTP request failed: {e}")
                await active_probe(reader, writer, port, result)
                writer.close()
                await writer.wait_closed()
                if port in (443, 8443):
                    await self.inspect_tls(host, port, result)
                    result.notes.append("TLS inspected")
            except Exception as e:
                result.errors.append(str(e))
                result.duration_s = time.time() - start
            return result
    async def run(self) -> List[ScanResult]:
        tasks = [
            self.probe(host, port)
            for host in self.config.hosts
            for port in self.config.ports
        ]
        results = await asyncio.gather(*tasks)
        results.sort(key=lambda r: (r.host, r.port))
        return results
def write_json(path: str, results: List[ScanResult]):
    data = {
        "schema_version": SCHEMA_VERSION,
        "results": [asdict(r) for r in results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(json.dumps(data, indent=2))
def write_csv(path: str, results: List[ScanResult]):
    header = ["host", "port", "reachable", "duration_s", "banner", "notes", "cert_expired", "cert_self_signed", "errors"]
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        print(",".join(header))
        for r in results:
            row = [
                r.host,
                r.port,
                r.reachable,
                f"{r.duration_s:.2f}",
                r.banner.replace("\n", " "),
                "; ".join(r.notes),
                r.certificate.get("cert_expired", ""),
                r.certificate.get("cert_self_signed", ""),
                "; ".join(r.errors),
            ]
            writer.writerow(row)
            print(",".join(map(str, row)))
def parse_args() -> ScannerConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--hosts-file")
    parser.add_argument("--ports", default=DEFAULT_PORTS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--json")
    parser.add_argument("--csv")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    if args.hosts_file:
        with open(args.hosts_file) as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.host:
        hosts = [args.host]
    else:
        print("Specify --host or --hosts-file")
        sys.exit(1)
    ports = parse_ports(args.ports)
    return ScannerConfig(
        hosts=hosts,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        json_out=args.json,
        csv_out=args.csv,
        verbose=args.verbose,
        insecure=args.insecure,
        ports_str=args.ports,
    )
def setup_signal_handler():
    def handler():
        print("Interrupted by user")
        sys.exit(1)
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, handler)
async def main():
    config = parse_args()
    setup_signal_handler()
    print(f"Scanning {len(config.hosts)} host(s) on ports: {config.ports_str}")
    scanner = AsyncPortScanner(config)
    results = await scanner.run()
    if config.json_out:
        write_json(config.json_out, results)
    if config.csv_out:
        write_csv(config.csv_out, results)
if __name__ == "__main__":
    asyncio.run(main())
