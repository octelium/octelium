import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, headers, timeout):
    opener = urllib.request.build_opener(NoRedirect)
    try:
        response = opener.open(urllib.request.Request(url, headers=headers), timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    except urllib.error.URLError as error:
        raise RuntimeError("SBOM request failed") from error

    with response:
        return response.status, response.headers, response.read()


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None:
        raise ValueError("SBOM URLs must use HTTPS without embedded credentials")
    if parsed.fragment:
        raise ValueError("SBOM URLs must not contain fragments")


def generate_sbom(repository, token, api_url="https://api.github.com", timeout=300, poll_interval=5):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("GITHUB_REPOSITORY must contain an owner and repository name")
    if timeout <= 0 or poll_interval <= 0:
        raise ValueError("SBOM timeout and poll interval must be positive")

    api_url = api_url.rstrip("/")
    validate_url(api_url)
    if urllib.parse.urlsplit(api_url).query:
        raise ValueError("GITHUB_API_URL must not contain a query")

    endpoint = f"{api_url}/repos/{repository}/dependency-graph/sbom"
    api_headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "octelium-sbom",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    if token:
        api_headers["Authorization"] = f"Bearer {token}"

    deadline = time.monotonic() + timeout

    def fetch(url, authenticated=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for the GitHub SBOM export")
        headers = api_headers if authenticated else {"User-Agent": "octelium-sbom"}
        return request(url, headers, min(30, remaining))

    status, _, body = fetch(f"{endpoint}/generate-report", authenticated=True)
    if status != 201:
        raise RuntimeError(f"GitHub SBOM generation returned HTTP {status}")

    result = json.loads(body)
    report_url = result.get("sbom_url") if isinstance(result, dict) else None
    if not isinstance(report_url, str) or not re.fullmatch(
        re.escape(f"{endpoint}/fetch-report/") + r"[A-Za-z0-9-]+", report_url
    ):
        raise ValueError("GitHub returned an invalid SBOM report URL")

    while True:
        status, headers, _ = fetch(report_url, authenticated=True)
        if status == 302:
            if not headers.get("Location"):
                raise ValueError("GitHub SBOM response is missing the download URL")
            download_url = urllib.parse.urljoin(report_url, headers["Location"])
            break
        if status != 202:
            raise RuntimeError(f"GitHub SBOM polling returned HTTP {status}")
        time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))

    for _ in range(6):
        validate_url(download_url)
        status, headers, body = fetch(download_url)
        if status == 200:
            sbom = json.loads(body)
            if (
                not isinstance(sbom, dict)
                or sbom.get("SPDXID") != "SPDXRef-DOCUMENT"
                or not isinstance(sbom.get("spdxVersion"), str)
                or not sbom["spdxVersion"].startswith("SPDX-")
                or not isinstance(sbom.get("packages"), list)
            ):
                raise ValueError("Downloaded SBOM is not an SPDX JSON document")
            return sbom
        if status not in (301, 302, 303, 307, 308):
            raise RuntimeError(f"SBOM download returned HTTP {status}")
        if not headers.get("Location"):
            raise ValueError("SBOM download redirect is missing the download URL")
        download_url = urllib.parse.urljoin(download_url, headers["Location"])

    raise RuntimeError("SBOM download exceeded the redirect limit")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export the current GitHub dependency graph as SPDX JSON")
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)

    try:
        sbom = generate_sbom(
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GH_TOKEN", ""),
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=args.output.parent) as directory:
            temporary = Path(directory) / "sbom.json"
            temporary.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
            temporary.replace(args.output)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"SBOM export failed: {error}", file=sys.stderr)
        return 1

    print(f"Saved GitHub dependency-graph SBOM to {args.output} ({len(sbom['packages'])} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
