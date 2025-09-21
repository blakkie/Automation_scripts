'''
Description: Hardened IOC extractor with OWASP-aligned security practices
- Reads plain text (file/stdin/Excel), extracts IOCs (IPs, domains, urls, hashes)
- Deduplicates with sets
- Chunks into groups and outputs JSON securely
'''

import sys, re, json, ipaddress, logging, os
from pathlib import Path
from urllib.parse import urlparse
from typing import Iterable, List
import pandas as pd
from uuid import uuid4

# logs events with timestamps & prevents huge input files(>10mb )
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

MAX_INPUT_SIZE = 10 * 1024 * 1024  #maximum input size will be 10mbps

#IP_address regex

ip_address_regex = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    r"|\[?[A-Fa-f0-9:]+\]?"
)

# Hashes
hash_patterns = [
    (re.compile(r"\b[a-fA-F0-9]{32}\b"), "md5"),
    (re.compile(r"\b[a-fA-F0-9]{40}\b"), "sha1"),
    (re.compile(r"\b[a-fA-F0-9]{64}\b"), "sha256"),
]

# URLs
url_regex = re.compile(r"\b(?:https?|ftp)://[^\s\$.?#].[^\s]*", re.IGNORECASE)

# Domains
domain_regex = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE
)

# sanitize input against injection attacks, path traversal!
def sanitize_value(val: str) -> str:
    return re.sub(r"[^\w\.\-:/]", "", val.strip())


# Securely load script.
def load_input(input_path: str) -> str:
    safe_path = Path(input_path).resolve()

    if not safe_path.exists():
        raise FileNotFoundError(f"File not found: {safe_path}")

    if safe_path.suffix.lower() == ".xlsx":
        df = pd.read_excel(safe_path, sheet_name=None)
        

        text = "\n".join(
            "\n".join(df[sheet].astype(str).stack().tolist())
            for sheet in df.keys()
        )
    else:
        raw = safe_path.read_bytes()
        if len(raw) > MAX_INPUT_SIZE:
            raise ValueError("Input file too large. Limit is 10 MB.")
        text = raw.decode("utf-8", errors="ignore")

    return text


# --- Extract IOCs
def iocs_extract(text: str):
    iocs = {
        "ips": set(),
        "hashes": set(),
        "urls": set(),
        "domains": set()
    }

    # IPs
    for match in ip_address_regex.findall(text):
        user = sanitize_value(match).strip("[]")

        candidate = user
        if ":" in user and user.count(":") == 1:
            left, right = user.rsplit(":", 1)
            if right.isdigit():
                candidate = left

        try:
            ip_obj = ipaddress.ip_address(candidate)
            iocs["ips"].add(str(ip_obj))
        except ValueError:
            continue

    # Hashes
    for regex, _ in hash_patterns:
        for h in regex.findall(text):
            iocs["hashes"].add(sanitize_value(h.lower()))

    # URLs
    for url in url_regex.findall(text):
        iocs["urls"].add(sanitize_value(url))

    # Domains
    for domain in domain_regex.findall(text):
        iocs["domains"].add(sanitize_value(domain.lower()))

    return {k: sorted(v) for k, v in iocs.items()}


# split iocs into chunks
def chunked(iterable: Iterable, size: int):
    it = list(iterable)
    for i in range(0, len(it), size):
        yield it[i:i + size]


# create json header
def make_chunk_objects(items: List[str], prefix: str, kind: str, desc_base: str, chunk_size: int):
    chunks = list(chunked(items, chunk_size))
    objects = []
    for i, chunk in enumerate(chunks, 1):
        obj = {
            "Type": kind,
            "Description": f"{desc_base} (chunk {i}/{len(chunks)})",
            "Values": chunk
        }
        filename = f"{prefix}_{kind}_{i}_{uuid4().hex}.json"
        objects.append((filename, obj))
    return objects


#accept user input
def main():
    print("## IOC EXTRACTOR")
    choice = input("Enter '1' to load file, '2' to paste text: ").strip()

    if choice == "1":
        input_path = input("Enter input file path: ").strip()
        text = load_input(input_path)
    else:
        print("Paste your text here (end with ENTER + Ctrl+D / Ctrl+Z):")
        text = sys.stdin.read()

    chunk_size = int(input("Enter chunk size (default 1000): ") or "1000")
    output_dir = Path("output_json").resolve()
    output_dir.mkdir(exist_ok=True)

    iocs = iocs_extract(text)

    # Process each IOC type separately
    for kind, values in iocs.items():
        objects = make_chunk_objects(values, str(output_dir / "ioc"), kind, f"Extracted {kind}", chunk_size)
        for filename, obj in objects:
            Path(filename).write_text(json.dumps(obj, indent=2), encoding="utf-8")
            logging.info("Written %d %s to %s", len(obj["Values"]), kind, filename)

    logging.info("Extraction complete. %d IPs, %d hashes, %d URLs, %d domains.",
                 len(iocs["ips"]), len(iocs["hashes"]), len(iocs["urls"]), len(iocs["domains"]))


if __name__ == "__main__":
    main()
