# Domainfinder

Domainfinder is a Python script that generates domain names by combining prefixes and suffixes, then checks their availability.

## Features

* Generates domain names from user-defined prefixes and suffixes
* Checks availability with RDAP over HTTPS, then falls back to WHOIS if RDAP cannot answer
* Treats an RDAP HTTP 404 as available and HTTP 200 as registered
* Uses Verisign RDAP for .com and .net, and the IANA RDAP bootstrap for other TLDs
* Saves free domains to a file
* Skips domains that were already checked
* Supports custom top-level domains (TLDs)
* Command-line interface

## Requirements

Python 3.9+

Install the pinned dependencies in `requirements.txt`. `python-whois` is only used when RDAP cannot answer.

## Installation

1. Clone the repository:
   `git clone https://github.com/caspii/domainfinder.git`
2. `cd domainfinder`
3. Install dependencies:
   `pip install -r requirements.txt`

## Usage

Edit the `input.txt` file:

* Add prefixes under the `--prefixes` section
* Add suffixes under the `--suffixes` section

Run the script:

`python find.py`

Each prefix is combined with each suffix and the TLD (`.com` by default).

Optional arguments:

`python find.py --tld .com --input custom_input.txt --output available_domains.txt --checked checked-domains.txt`

## Example

If your `input.txt` contains:

```
--prefixes
signup
--suffixes
abc
now
zap
```

The script checks:

* signupabc.com
* signupnow.com
* signupzap.com

## How lookups work

RDAP over HTTPS is the primary check, so the script still works on networks that block WHOIS (port 43) or time out.

* `.com` uses `https://rdap.verisign.com/com/v1/domain/<domain>`
* `.net` uses `https://rdap.verisign.com/net/v1/domain/<domain>`
* Other TLDs use the IANA bootstrap file at `https://data.iana.org/rdap/dns.json` to find that TLD's RDAP server

An HTTP 404 means the domain is available. An HTTP 200 means it is taken. Any other RDAP result (connection error, timeout, or an unexpected status) falls back to `python-whois`.

On python-whois 0.9.6, an unregistered domain raises `whois.exceptions.WhoisDomainNotFoundError`. Older releases raise `whois.parser.PywhoisError`, which 0.9.6 removed. The fallback resolves whichever of those classes the installed library actually provides, so a failed lookup does not crash inside the error handler.

Domains that neither method can classify are logged and left out of the checked file, so a later run can retry them. The script then exits with status 1.

## Output

The script prints `FREE` or `TAKEN` for each domain it can classify.
Free domains are appended to `free-domains.txt` (or the file passed to `--output`).
Every classified domain is appended to `checked-domains.txt` (or the file passed to `--checked`).

## Tests

`python -m unittest tests.test_find`

## Advanced Usage

```
--tld: Top-level domain to append (default: .com)
--input: Input file (default: input.txt)
--output: File for free domains (default: free-domains.txt)
--checked: File of domains already classified (default: checked-domains.txt)
```

Example:

`python find.py --tld .org --input my_inputs.txt --output available_org_domains.txt`

## Additional Resources

For more information on domain finding strategies, check out this blog post: [Finding a Domain](http://casparwre.de/blog/finding-a-domain/)
