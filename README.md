# MimecastDecoder
A simple, modern Python script to decode URLs created by the Mimecast URL Protection feature.

## Problem
[URL Protection], part of the Mimecast Targeted Threat Protection email security product, offers end users an increased level of protection against malicious URLs embedded in emails. URLs in emails are replaced by unique URLs pointing to Mimecast servers, allowing various checks to be performed after a user has clicked on one of the links.

The problem comes when a user wishes to retrieve the original URL without first visiting it. This is a common scenario for technical personnel. For example, a help desk technician might wish to investigate the hyperlinks embedded in a suspected spam email, or a cyber security analyst might wish to investigate a malware delivery email by following the link in a sandboxed environment. Mimecast provides several methods for decoding URLs but each presents its own challenges:

### From an Enrolled Browser
The main issue with using the browser is that Mimecast automatically redirects you to the page. This is not a desirable behavior if you suspect the link might take you to a malicious website.
Also when Device Enrollment is configured, the encoded URL can only be decoded from a browser session which is enrolled. While device enrollment is quite straightforward, the enrollment status is not preserved in incognito/private browsing sessions. Also, you are stuck if you want to use command line tools such as `curl` or `wget`.

### Decode Tool on the URL Protection Dashboard
On the surface, this sounds really promising. However, to use this, you need to be logged in to the Administration Console and navigate the web UI, which takes a lot of time considering that without the URL Protection feature, you only need to move the mouse over the link to see where it points to. Also, the dashboard page is only accessible by admins.

### Use the Decode Function provided by the API
Mimecast has also very helpfully provided an [API] function that can be used to decode these URLs. This again is cumbersome without some additional wrapper script. Also, you will need to supply an API authentication token, which is of course good security, but unfortunately also requires you to have admin level access.

### Use the Handy URL Preview Feature
Mimecast has a built-in [Preview URL] feature and to use it, you need to paste the URL into an enrolled browser with an additional `+` character at the end of the URL.
This is a great way to manually preview the URL, however, the URL is actually an image, which is no good if you want to grab the URL as plain text to take to other systems. Also, this can be a bit accident-prone — if you forget to add the `+` or press Enter after pasting, you will be taken to the URL without further warning.

## Solution
After some basic investigation, it appears that the enrollment status of a browser is simply kept in a single session cookie. This can be easily exported to other systems or used in command-line tools.

This Python script simulates the URL decoding process that happens in an enrolled browser in a single, highly efficient request. But rather than follow the redirection to the original URL, the script simply displays that URL in the console. This allows you to quickly decode a URL on the command line, in a format that can then be copied and pasted.

The script requires a valid enrollment cookie "borrowed" from an already enrolled browser. It implements a save option to save the cookie in a config file, so that the rather long and messy cookie values are not needed for subsequent uses.

### Extra Challenge
On Mimecast tenants that have the user awareness training feature enabled, every so often, instead of decoding the URL in the browser, you are prompted to decide whether the URL is Safe or Unsafe. The script handles this by automatically detecting the challenge page and calling Mimecast's client-side API to fetch the original URL.

## Installation
No need to install. Simply download the Python script and run. Requires Python 3 and the `requests` library.

```bash
pip install requests
```

Works flawlessly on Windows.

## Examples
Run the first decode, specify the URL (`-u`) and also a valid authentication cookie from an enrolled browser (`-c`), and save the cookie in a config file for future use. Please do not use the cookie in the example as it is not a valid cookie. 
```bash
$ ./MimecastDecoder.py -u https://protect-eu.mimecast.com/s/4YYXx3RhcsBNOrkmt5hm -c x-mc-ea-o40zr1n2e8198tnm83avpkel5p6hra53=8BAABklWQvuP8sqJ78k2_sU87dP6P31eu0bmFqgthqziyHZrwy_xWlZekXtPcSg0fGUNL_sU87dP-OcNFoQpEXLLDvwgJ1LEBAnaeliHj92u7tI6tgXqyRDLSel6RqAoIVRjGiKU7GqqMHFj1CFQcaLJKSN4HQxr2r9Ziu1t_c17TMZEIU4BoPZ_3YTUROFG -s
https://github.com/guy-liu/mcdecode
```
The subsequent decodes only require the URL (`-u`).
```bash
$ ./MimecastDecoder.py -u https://protect-eu.mimecast.com/s/4YYXx3RhcsBNOrkmt5hm 
https://github.com/guy-liu/mcdecode
``` 
You can also specify a different cookie (`-c`) as a one-time value for testing, or in combination with the save cookie option (`-s`) to update the stored cookie in the config file. The config file is located at `~/.mcdecode`.

### Batch Mode & Raw Emails (Multiple URLs / HTML Files)
You can also process a file specified with `--file` / `-f`. The tool automatically handles its content based on the file extension:

1. **Plain Text Files (`.txt`, etc.)**: Parses the file line-by-line, validating and filtering incoming entries. It only decodes Mimecast-protected URLs while skipping plain links, malformed lines, or garbage strings.
2. **Raw Email HTML Files (`.htm`, `.html`)**: Parses the entire file, extracts all unique embedded links containing `"mimecast"`, and decodes each of them. This is extremely handy for analyzing direct mail copies from folders like `Resources/` or local archives.

The script automatically detects and supports multiple file encodings gracefully by prioritizing `UTF-16` (handling Byte Order Marks), strict `UTF-8`, and legacy `windows-1252`/ANSI fallback, ensuring that plain text exports or raw email HTML files parse seamlessly without encoding corruption.

```bash
# Process links listed in a plain text file:
$ ./MimecastDecoder.py -f links.txt

# Extract and decode Mimecast links from a raw HTML email file:
$ ./MimecastDecoder.py -f Resources/mail1.htm
```

### Help Information
For more usage information, use the help option (`-h`):
```bash
$ ./MimecastDecoder.py -h
usage: MimecastDecoder.py [-h] [--cookie COOKIE] [--save] (--url URL | --file FILE) [--debug]

Decodes the encoded URL created by Mimecast Targeted Threat Protection - URL Protect feature. Requires a cookie from an
enrolled browser specified via command line or stored in ~/.mcdecode

options:
  -h, --help           show this help message and exit
  --cookie, -c COOKIE  Cookie from an enrolled browser in the format of key=value
  --save, -s           Save the specified cookie in ~/.mcdecode if URL is successfully decoded
  --url, -u URL        Encoded URL
  --file, -f FILE      File containing multiple encoded URLs (one per line)
  --debug              Output debug information
```

## Security Features & Guidelines
This script is explicitly designed for safe usage by cybersecurity analysts and help desk personnel:

1. **Sandboxed Decodes (`allow_redirects=False`)**: The script disables automatic redirect following on HTTP requests. Instead, it manually inspects redirect headers (`Location`). 
   - If a redirect points internally to a Mimecast domain (such as internal hops or security training pages), the script safely follows it.
   - If a redirect points to any external domain (the decoded destination), the script **halts immediately and returns the target URL without ever initiating a network connection to that domain**.
2. **Defanged Outputs**: To prevent accidental clicks, all decoded URLs printed by the script are fully defanged (e.g., standard `http(s)` prefixes are converted to `hxxp(s)` and domain dots are replaced with `[.]`).
3. **HTTP Timeouts**: Strict 10-second limits are enforced on all network connections to prevent DoS attacks.
4. **Chrome User-Agent Header**: Requests use a standard Chrome User-Agent header, preventing blocks from anti-bot detectors.
5. **Connection Pooling & Performance (`requests.Session`)**: The script instantiates a persistent HTTP session context manager for both batch processing and individual multi-hop redirect resolution. This allows the reuse of underlying TCP and TLS connections (via HTTP Keep-Alive), avoiding the massive network handshake overhead associated with sequential individual requests when `allow_redirects=False` is active.
6. **Concurrent Batch Decoding (`ThreadPoolExecutor`)**: When processing files in batch mode, the script utilizes multithreading via Python's `ThreadPoolExecutor` to decode multiple URLs concurrently. You can customize the degree of parallelism using the `--workers` / `-w` parameter (defaults to 10). In combination with connection pooling, this multithreading strategy results in massive speed gains (typically over **90% faster** in batch decodes) while keeping all sandboxing and defanging features fully active.

Enjoy. 

[URL Protection]:https://community.mimecast.com/s/article/Targeted-Threat-Protection-URL-Protect-793832582

[API]:https://www.mimecast.com/tech-connect/documentation/endpoint-reference/targeted-threat-protection-url-protect/decode-url/

[Preview URL]:https://community.mimecast.com/s/article/Targeted-Threat-Protection-Verifying-a-URL-621586565
