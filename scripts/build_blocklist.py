import re
import urllib.request
from pathlib import Path

HAGEZI_URL = (
    "https://cdn.jsdelivr.net/gh/"
    "hagezi/dns-blocklists@latest/"
    "wildcard/tif-onlydomains.txt"
)

ADOBE_URL = "https://a.dove.isdumb.one/pihole.txt"

OUTPUT_FILE = Path("blocked-names.txt")

DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)+$"
)


def download(url):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "dnscrypt-blocklists-updater/1.0"
        }
    )

    with urllib.request.urlopen(request, timeout=180) as response:
        if response.status != 200:
            raise RuntimeError(
                f"Download failed: HTTP {response.status} for {url}"
            )

        return response.read().decode("utf-8", errors="replace")


def parse_hagezi(text):
    domains = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # HaGeZi DNSCrypt wildcard format:
        # *.example.com
        if line.startswith("*."):
            line = line[2:]

        line = line.rstrip(".")

        if DOMAIN_RE.fullmatch(line):
            domains.add(line.lower())
        else:
            raise RuntimeError(
                f"Invalid HaGeZi domain entry: {line}"
            )

    return domains


def parse_adobe(text):
    domains = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Accept both:
        #
        # domain.example
        #
        # and hosts-style:
        #
        # 0.0.0.0 domain.example
        #
        parts = line.split()

        if len(parts) == 1:
            domain = parts[0]
        elif len(parts) == 2 and parts[0] in (
            "0.0.0.0",
            "127.0.0.1",
            "::",
            "::1",
        ):
            domain = parts[1]
        else:
            raise RuntimeError(
                f"Invalid Adobe list entry: {line}"
            )

        domain = domain.lstrip("*.")
        domain = domain.rstrip(".")

        if DOMAIN_RE.fullmatch(domain):
            domains.add(domain.lower())
        else:
            raise RuntimeError(
                f"Invalid Adobe domain entry: {domain}"
            )

    return domains


def main():
    print("Downloading HaGeZi TIF...")
    hagezi_text = download(HAGEZI_URL)

    print("Downloading Adobe telemetry list...")
    adobe_text = download(ADOBE_URL)

    print("Processing HaGeZi...")
    hagezi_domains = parse_hagezi(hagezi_text)

    print("Processing Adobe...")
    adobe_domains = parse_adobe(adobe_text)

    print(f"HaGeZi domains: {len(hagezi_domains):,}")
    print(f"Adobe domains:  {len(adobe_domains):,}")

    combined = hagezi_domains | adobe_domains

    print(f"Combined unique domains: {len(combined):,}")

    if len(combined) < 100000:
        raise RuntimeError(
            "Safety check failed: combined blocklist is unexpectedly small."
        )

    output = [
        "# DNSCrypt combined blocklist",
        "# Sources:",
        "# HaGeZi TIF: "
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"
        "wildcard/tif-onlydomains.txt",
        "# Adobe telemetry: https://a.dove.isdumb.one/pihole.txt",
        "#",
        "# Generated automatically by GitHub Actions.",
        "# One domain per line.",
        "",
    ]

    output.extend(sorted(combined))

    OUTPUT_FILE.write_text(
        "\n".join(output) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"Written: {OUTPUT_FILE}")
    print(f"Output size: {OUTPUT_FILE.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
