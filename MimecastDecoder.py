#!/usr/bin/env python3
"""
Decodes URLs created by the Mimecast URL Protection feature.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import html
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
import requests

CONFIG_FILE = Path.home() / ".mcdecode"


class DecodeError(Exception):
    """Custom exception for URL decoding failures."""
    pass


def parse_cookie_arg(cookie_str: str) -> tuple[str, str]:
    """Parses a cookie string in the format key=value."""
    if "=" not in cookie_str:
        print("ERROR: The specified cookie is not in the format: cookie=value")
        sys.exit(1)

    # Split by the first '=' to allow value to contain '=' if any
    cookie_key, cookie_value = cookie_str.split("=", 1)
    return cookie_key.strip(), cookie_value.strip()


def load_cookie() -> tuple[str, str]:
    """Loads the cookie from the configuration file."""
    if not CONFIG_FILE.exists():
        print("ERROR: A valid cookie needs to be specified either via command line or cookie file.")
        sys.exit(1)

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            line = f.read().strip()
        if not line:
            print("ERROR: Cookie file is empty.")
            sys.exit(1)

        cookie_key, cookie_value = parse_cookie_arg(line)
        return cookie_key, cookie_value
    except Exception as e:
        print(f"ERROR: Failed to read cookie from {CONFIG_FILE}: {e}")
        sys.exit(1)


def save_cookie(cookie_key: str, cookie_value: str) -> None:
    """Saves the cookie to the configuration file."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(f"{cookie_key}={cookie_value}")
    except Exception as e:
        print(f"ERROR: Failed to save cookie to {CONFIG_FILE}: {e}")


def read_file_content(file_path: str) -> str:
    """Reads a file trying multiple encodings to handle UTF-8, UTF-16, and legacy text."""
    encodings = ["utf-16", "utf-8", "windows-1252"]
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue
    # Ultimate fallback ignoring error bytes
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def extract_mimecast_urls_from_html(html_content: str) -> list[str]:
    """Extracts all unique URLs containing 'mimecast' from HTML content using regex."""
    # Matches http:// or https:// followed by non-whitespace, non-quotes, non-brackets
    url_pattern = re.compile(r'https?://[^\s"\'<>]+')
    unescaped_content = html.unescape(html_content)
    found_urls = url_pattern.findall(unescaped_content)
    
    seen = set()
    mimecast_urls = []
    for url in found_urls:
        if "mimecast" in url.lower():
            if url not in seen:
                seen.add(url)
                mimecast_urls.append(url)
    return mimecast_urls


def is_mimecast_url(url: str) -> bool:
    """Checks if a URL is a Mimecast-encoded URL."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        netloc = parsed.netloc.lower()
        # Mimecast domains typically include 'mimecastprotect.com' or 'mimecast.com'
        if "mimecastprotect.com" not in netloc and "mimecast.com" not in netloc:
            return False
        # Mimecast protective link paths usually start with /s/ or /t/ or /r/
        if not parsed.path.startswith(("/s/", "/t/", "/r/")):
            return False
        return True
    except Exception:
        return False


def is_mimecast_domain(url: str) -> bool:
    """Checks if a URL has a Mimecast domain (netloc)."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        return "mimecastprotect.com" in netloc or "mimecast.com" in netloc
    except Exception:
        return False


def defang_url(url: str) -> str:
    """Converts a URL into a non-clickable defanged format for security."""
    if not url:
        return url
    defanged = url
    # Replace http/https with hxxp/hxxps
    defanged = re.sub(r'^https?:', lambda m: m.group(0).lower().replace('http', 'hxxp'), defanged, flags=re.IGNORECASE)
    
    # Defang netloc (authority) dots
    scheme_match = re.match(r'^(hxxps?://)([^/]+)', defanged, flags=re.IGNORECASE)
    if scheme_match:
        scheme, domain = scheme_match.groups()
        defanged_domain = domain.replace('.', '[.]')
        defanged = scheme + defanged_domain + defanged[scheme_match.end():]
    else:
        domain_match = re.match(r'^([^/]+)', defanged)
        if domain_match:
            domain = domain_match.group(1)
            if '.' in domain:
                defanged_domain = domain.replace('.', '[.]')
                defanged = defanged_domain + defanged[domain_match.end():]
    return defanged


def decode_url(url: str, cookie_key: str, cookie_value: str, session: requests.Session = None, debug: bool = False) -> str:
    """Decodes the Mimecast URL using HTTP requests without following non-Mimecast redirects."""
    cookies = {cookie_key: cookie_value}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    current_url = url
    max_hops = 5

    for hop in range(max_hops):
        if debug:
            print(f"DEBUG: Making GET request to {current_url} (hop {hop + 1})")
            if hop == 0:
                print(f"DEBUG: Using cookie: {cookie_key}={cookie_value[:15]}...{cookie_value[-15:] if len(cookie_value) > 30 else ''}")

        try:
            # We set allow_redirects=False to prevent connecting to untrusted destination domains
            if session:
                response = session.get(current_url, allow_redirects=False, timeout=10)
            else:
                response = requests.get(current_url, cookies=cookies, headers=headers, allow_redirects=False, timeout=10)
        except requests.RequestException as e:
            raise DecodeError(f"Network request failed: {e}")

        if debug:
            print(f"DEBUG: Response Status: {response.status_code}")
            if response.headers.get("Location"):
                print(f"DEBUG: Redirect Location header: {response.headers['Location']}")

        # Check for 3xx redirect
        if 300 <= response.status_code < 400 and "Location" in response.headers:
            redirect_url = response.headers["Location"]
            if debug:
                print(f"DEBUG: Encountered redirect to {redirect_url}")

            # If the redirect is to an external untrusted domain, stop and return it immediately!
            if not is_mimecast_domain(redirect_url):
                if debug:
                    print("DEBUG: Redirect target is an external domain. Safely returning it without connecting.")
                return redirect_url

            # If it is a Mimecast URL, we can follow it safely (it's still on Mimecast's servers)
            current_url = redirect_url
            continue

        # If it's a 200 OK (or any other non-redirect), we process the response body
        response_text = response.text.strip()
        
        # Case 1: The response body itself is the decoded URL (common in modern Mimecast)
        if ("\n" not in response_text and " " not in response_text and 
                "<" not in response_text and "." in response_text):
            if debug:
                print("DEBUG: Successfully decoded URL directly from response body.")
            return response_text

        # Case 2: We landed on an enrollment page
        if "enrollment" in response.url or "enrollment" in response_text.lower():
            raise DecodeError("URL decode failed. Ensure a valid, enrolled cookie is specified.")

        # Case 3: We landed on a user challenge / email security training page
        # Extract cache key and make API call to fetch original URL
        cache_key = None
        for source_url in (current_url, response.url):
            # Extract key from query string or fragment (hash) using a robust regex search
            match = re.search(r"[?&]key=([^&/#?]+)", source_url)
            if match:
                cache_key = match.group(1)
                break

        if cache_key:
            if debug:
                print(f"DEBUG: Security challenge detected. Extracted cacheKey: {cache_key}")
                print("DEBUG: Making API call to retrieve original URL.")

            parsed_url = urlparse(current_url)
            api_url = f"{parsed_url.scheme}://{parsed_url.netloc}/api/ttp/url/get-page-data"
            payload = {"data": [{"cacheKey": cache_key, "pageType": "user_challenge"}]}

            try:
                if session:
                    api_response = session.post(api_url, json=payload, allow_redirects=False, timeout=10)
                else:
                    api_response = requests.post(api_url, cookies=cookies, headers=headers, json=payload, allow_redirects=False, timeout=10)
                api_response.raise_for_status()
                data = api_response.json()
                original_url = data["data"][0]["originalUrl"]
                return original_url
            except Exception as e:
                if debug:
                    print(f"DEBUG: API response: {api_response.text if 'api_response' in locals() else 'None'}")
                raise DecodeError(f"Failed to retrieve URL from security challenge API: {e}")

        # If all else fails
        if debug:
            print(f"DEBUG: Response body snippet: {response_text[:500]}")
        raise DecodeError(f"Unexpected response format or page encountered. Status: {response.status_code}")

    raise DecodeError("Exceeded maximum redirects while resolving Mimecast URL.")


def main() -> None:
    program_info = (
        "Decodes the encoded URL created by Mimecast Targeted Threat Protection - URL Protect feature. "
        "Requires a cookie from an enrolled browser specified via command line or stored in ~/.mcdecode"
    )

    parser = argparse.ArgumentParser(description=program_info)
    parser.add_argument("--cookie", "-c", help="Cookie from an enrolled browser in the format of key=value")
    parser.add_argument("--save", "-s", help="Save the specified cookie in ~/.mcdecode if URL is successfully decoded", action="store_true")
    
    # Mutually exclusive group for URL or File input
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", "-u", help="Encoded URL")
    group.add_argument("--file", "-f", help="File containing multiple encoded URLs (one per line)")
    
    parser.add_argument("--workers", "-w", type=int, default=10, help="Number of concurrent workers for batch processing (default: 10)")
    parser.add_argument("--debug", help="Output debug information", action="store_true")

    args = parser.parse_args()

    cookie_given = False
    if args.cookie:
        cookie_key, cookie_value = parse_cookie_arg(args.cookie)
        cookie_given = True
    else:
        cookie_key, cookie_value = load_cookie()

    success = False
    session = requests.Session()
    
    # Configure connection pooling to match the number of workers/threads to avoid bottlenecks
    pool_size = args.workers if not args.url else 10
    adapter = requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.cookies.set(cookie_key, cookie_value)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })

    with session:
        if args.url:
            if not is_mimecast_url(args.url):
                # Print as-is if it's already a decoded/non-Mimecast URL
                print(defang_url(args.url))
                sys.exit(0)
                
            try:
                decoded = decode_url(args.url, cookie_key, cookie_value, session=session, debug=args.debug)
                print(defang_url(decoded))
                success = True
            except DecodeError as e:
                print(f"ERROR: {e}")
                sys.exit(1)
        else:
            # File processing
            if not os.path.exists(args.file):
                print(f"ERROR: File not found: {args.file}")
                sys.exit(1)

            try:
                content = read_file_content(args.file)
            except Exception as e:
                print(f"ERROR: Failed to read file {args.file}: {e}")
                sys.exit(1)

            # Check file extension
            _, ext = os.path.splitext(args.file.lower())
            if ext in (".htm", ".html"):
                if args.debug:
                    print(f"DEBUG: Processing HTML file: {args.file}")
                urls = extract_mimecast_urls_from_html(content)
            else:
                if args.debug:
                    print(f"DEBUG: Processing plain text file: {args.file}")
                urls = [line.strip() for line in content.splitlines() if line.strip()]

            mimecast_urls = [url for url in urls if is_mimecast_url(url)]

            if not mimecast_urls:
                success = False
            else:
                def process_url(url: str):
                    try:
                        decoded = decode_url(url, cookie_key, cookie_value, session=session, debug=args.debug)
                        return url, defang_url(decoded), None
                    except DecodeError as e:
                        return url, None, str(e)

                decoded_any = False
                if args.debug:
                    print(f"DEBUG: Spawning ThreadPoolExecutor with {args.workers} workers...")
                
                with ThreadPoolExecutor(max_workers=args.workers) as executor:
                    results = executor.map(process_url, mimecast_urls)
                    
                    for url, decoded, error in results:
                        if decoded:
                            print(decoded)
                            decoded_any = True
                        else:
                            print(f"ERROR decoding {url}: {error}", file=sys.stderr)
                success = decoded_any

    if args.save and cookie_given and success:
        if args.debug:
            print(f"DEBUG: Saving cookie to {CONFIG_FILE}")
        save_cookie(cookie_key, cookie_value)


if __name__ == "__main__":
    main()
