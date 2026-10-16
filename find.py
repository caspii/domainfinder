#!/usr/bin/env python
"""Generate prefix+suffix domains and report which ones are available."""

import argparse
import importlib
import json
import logging
import sys
import urllib.error
import urllib.request
from time import sleep
from urllib.parse import quote

IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
VERISIGN_RDAP_BASES = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
}
USER_AGENT = "domainfinder"
REQUEST_TIMEOUT = 15

# services list from https://data.iana.org/rdap/dns.json, loaded once per run
_bootstrap_services = None


class AvailabilityUnknown(Exception):
    """RDAP and WHOIS both failed to decide whether a domain is registered."""


def parse_arguments():
    parser = argparse.ArgumentParser(description="Check domain availability")
    parser.add_argument("--tld", default=".com", help="Top-level domain to check")
    parser.add_argument("--input", default="input.txt", help="Input file path")
    parser.add_argument("--output", default="free-domains.txt", help="Output file path")
    parser.add_argument("--checked", default="checked-domains.txt", help="File to track all checked domains")
    return parser.parse_args()


def read_input_file(file_path):
    prefixes, suffixes = [], []
    reading_prefixes = False

    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line == "--prefixes":
                    reading_prefixes = True
                elif line == "--suffixes":
                    reading_prefixes = False
                elif line:
                    if reading_prefixes:
                        prefixes.append(line)
                    else:
                        suffixes.append(line)
    except OSError as exc:
        logging.error(f"Error reading input file: {exc}")
        sys.exit(1)

    return prefixes, suffixes


def generate_domains(prefixes, suffixes, tld):
    return [f"{pre}{suff}{tld}" for pre in prefixes for suff in suffixes]


def read_checked_domains(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return set(line.strip() for line in handle)
    except OSError:
        return set()


def normalize_tld(tld):
    return tld.strip().strip(".").lower()


def _request(url, timeout=REQUEST_TIMEOUT):
    """Return (status, body). HTTP error statuses are returned, not raised."""
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        # HTTPError is a URLError subclass. Catch it here so a 404 stays a
        # status code instead of looking like a transport failure.
        payload = exc.read() if exc.fp is not None else b""
        return exc.code, payload


def load_rdap_bootstrap(timeout=REQUEST_TIMEOUT):
    global _bootstrap_services
    if _bootstrap_services is not None:
        return _bootstrap_services

    try:
        status, body = _request(IANA_RDAP_BOOTSTRAP_URL, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AvailabilityUnknown(f"IANA RDAP bootstrap failed: {exc}") from exc

    if status != 200:
        raise AvailabilityUnknown(f"IANA RDAP bootstrap returned HTTP {status}")

    try:
        payload = json.loads(body.decode("utf-8"))
        services = payload["services"]
    except (ValueError, KeyError, UnicodeError) as exc:
        raise AvailabilityUnknown(f"IANA RDAP bootstrap was not usable: {exc}") from exc

    _bootstrap_services = services
    return services


def rdap_base_url(tld, timeout=REQUEST_TIMEOUT):
    label = normalize_tld(tld)
    if label in VERISIGN_RDAP_BASES:
        return VERISIGN_RDAP_BASES[label]

    for names, urls in load_rdap_bootstrap(timeout=timeout):
        normalized = [str(name).lower() for name in names]
        if label in normalized and urls:
            base = str(urls[0])
            return base if base.endswith("/") else base + "/"

    raise AvailabilityUnknown(f"No RDAP server is published for .{label}")


def rdap_domain_url(domain, tld, timeout=REQUEST_TIMEOUT):
    base = rdap_base_url(tld, timeout=timeout)
    return f"{base}domain/{quote(domain, safe='.')}"


def check_rdap(domain, tld, timeout=REQUEST_TIMEOUT):
    """Return True when RDAP says the domain is free, False when it is taken.

    RFC 7480 uses HTTP 404 for an object the registry does not have, and
    HTTP 200 when the object is registered.
    """
    url = rdap_domain_url(domain, tld, timeout=timeout)
    try:
        status, _body = _request(url, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AvailabilityUnknown(f"RDAP request failed: {exc}") from exc

    if status == 404:
        return True
    if status == 200:
        return False
    raise AvailabilityUnknown(f"RDAP returned HTTP {status}")


def not_found_exceptions():
    """Exception types that mean python-whois found no registration.

    python-whois 0.9.6 removed whois.parser.PywhoisError. Looking that
    name up inside an except clause raises AttributeError and hides the
    original failure. Older releases still raise parser.PywhoisError for
    an unregistered domain, and 0.9.6 raises WhoisDomainNotFoundError.
    """
    try:
        import whois
    except ImportError:
        return tuple()

    found = []
    exceptions_mod = _load_whois_attr("whois.exceptions", whois, "exceptions")
    modern = getattr(exceptions_mod, "WhoisDomainNotFoundError", None) if exceptions_mod else None
    if isinstance(modern, type) and issubclass(modern, BaseException):
        found.append(modern)

    # Only the legacy class means "not registered". On 0.9.6 the same
    # name is a base class for quota and transport errors, so ignore it
    # when the specific not-found type exists.
    if not found:
        parser_mod = _load_whois_attr("whois.parser", whois, "parser")
        legacy = getattr(parser_mod, "PywhoisError", None) if parser_mod else None
        if isinstance(legacy, type) and issubclass(legacy, BaseException):
            found.append(legacy)

    return tuple(found)


def _load_whois_attr(module_name, whois_mod, attr_name):
    try:
        return importlib.import_module(module_name)
    except ImportError:
        return getattr(whois_mod, attr_name, None)


def check_whois(domain):
    """Return True when WHOIS says the domain is free, False when it is taken."""
    try:
        import whois
    except ImportError as exc:
        raise AvailabilityUnknown(
            "python-whois is not installed, so the WHOIS fallback is unavailable"
        ) from exc

    missing = not_found_exceptions()
    try:
        result = whois.whois(domain)
    except missing:
        return True
    except Exception as exc:
        raise AvailabilityUnknown(f"WHOIS lookup failed: {exc}") from exc

    domain_name = result.get("domain_name") if isinstance(result, dict) else getattr(result, "domain_name", None)
    if not domain_name:
        return True
    return False


def domain_is_available(domain, tld, timeout=REQUEST_TIMEOUT):
    """RDAP first. WHOIS only when RDAP cannot answer."""
    try:
        return check_rdap(domain, tld, timeout=timeout)
    except AvailabilityUnknown as rdap_error:
        logging.info(f"RDAP could not check {domain} ({rdap_error}); trying WHOIS")
        try:
            return check_whois(domain)
        except AvailabilityUnknown as whois_error:
            raise AvailabilityUnknown(f"RDAP: {rdap_error}; WHOIS: {whois_error}") from whois_error


def check_domains(domains, tld, output_file, checked_file, timeout=REQUEST_TIMEOUT):
    """Append free domains to output_file and every decided domain to checked_file.

    Returns the number of domains that could not be checked.
    """
    failed = 0
    with open(output_file, "a", encoding="utf-8") as free_file, open(checked_file, "a", encoding="utf-8") as checked:
        for domain in domains:
            sleep(0.5)
            try:
                available = domain_is_available(domain, tld, timeout=timeout)
            except AvailabilityUnknown as exc:
                failed += 1
                logging.error(f"{domain} could not be checked: {exc}")
                continue

            if available:
                logging.info(f"{domain} is FREE")
                free_file.write(f"{domain}\n")
                free_file.flush()
            else:
                logging.info(f"{domain} is TAKEN")
            checked.write(f"{domain}\n")
            checked.flush()
    return failed


def main():
    args = parse_arguments()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    prefixes, suffixes = read_input_file(args.input)
    domains = generate_domains(prefixes, suffixes, args.tld)
    checked_domains = read_checked_domains(args.checked)
    domains_to_check = [domain for domain in domains if domain not in checked_domains]

    failed = check_domains(domains_to_check, args.tld, args.output, args.checked)
    logging.info("DONE!")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
