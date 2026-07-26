#!/usr/bin/env python3
"""
Decodes URLs created by the Mimecast URL Protection feature.
"""

import argparse
import json
import os
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


def decode_url(url: str, cookie_key: str, cookie_value: str, debug: bool = False) -> str:
    """Decodes the Mimecast URL using a single HTTP request with auto-redirects."""
    cookies = {cookie_key: cookie_value}

    if debug:
        print(f"DEBUG: Making GET request to {url}")
        print(f"DEBUG: Using cookie: {cookie_key}={cookie_value[:15]}...{cookie_value[-15:] if len(cookie_value) > 30 else ''}")

    try:
        # One request to rule them all (automatic redirect following)
        response = requests.get(url, cookies=cookies, allow_redirects=True)
    except requests.RequestException as e:
        raise DecodeError(f"Network request failed: {e}")

    if debug:
        print(f"DEBUG: Final Response URL: {response.url}")
        print(f"DEBUG: Final Response Status: {response.status_code}")

    # Case 1: The response body itself is the decoded URL (common in modern Mimecast)
    response_text = response.text.strip()
    if response_text.startswith(("http://", "https://")) and "\n" not in response_text:
        if debug:
            print("DEBUG: Successfully decoded URL directly from response body.")
        return response_text

    # Case 2: We landed on an enrollment page
    if "enrollment" in response.url or "enrollment" in response_text.lower():
        raise DecodeError("URL decode failed. Ensure a valid, enrolled cookie is specified.")

    # Case 3: We landed on a user challenge / email security training page
    # Extract cache key and make API call to fetch original URL
    parsed_url = urlparse(response.url)
    query_params = dict(q.split("=", 1) for q in parsed_url.query.split("&") if "=" in q)
    cache_key = query_params.get("key")

    if cache_key:
        if debug:
            print(f"DEBUG: Security challenge detected. Extracted cacheKey: {cache_key}")
            print("DEBUG: Making API call to retrieve original URL.")

        api_url = f"{parsed_url.scheme}://{parsed_url.netloc}/api/ttp/url/get-page-data"
        payload = {"data": [{"cacheKey": cache_key, "pageType": "user_challenge"}]}

        try:
            api_response = requests.post(api_url, cookies=cookies, json=payload)
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
    raise DecodeError(f"Unexpected response format or page encountered. Final URL: {response.url}")


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
    
    parser.add_argument("--debug", help="Output debug information", action="store_true")

    args = parser.parse_args()

    cookie_given = False
    if args.cookie:
        cookie_key, cookie_value = parse_cookie_arg(args.cookie)
        cookie_given = True
    else:
        cookie_key, cookie_value = load_cookie()

    success = False
    if args.url:
        if not is_mimecast_url(args.url):
            # Print as-is if it's already a decoded/non-Mimecast URL
            print(args.url)
            sys.exit(0)
            
        try:
            decoded = decode_url(args.url, cookie_key, cookie_value, args.debug)
            print(decoded)
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
            with open(args.file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"ERROR: Failed to read file {args.file}: {e}")
            sys.exit(1)

        decoded_any = False
        for url in urls:
            if not is_mimecast_url(url):
                continue  # Skip comments, non-HTTP, normal non-Mimecast URLs
            try:
                decoded = decode_url(url, cookie_key, cookie_value, args.debug)
                print(decoded)
                decoded_any = True
            except DecodeError as e:
                print(f"ERROR decoding {url}: {e}", file=sys.stderr)
        success = decoded_any

    if args.save and cookie_given and success:
        if args.debug:
            print(f"DEBUG: Saving cookie to {CONFIG_FILE}")
        save_cookie(cookie_key, cookie_value)


if __name__ == "__main__":
    main()
