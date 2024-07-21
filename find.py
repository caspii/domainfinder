#!/usr/bin/env python
import argparse
import sys
from time import sleep
import logging
from pathlib import Path

try:
    import whois
except ImportError:
    print("ERROR: This script requires the python-whois module to run.")
    print("   You can install it via 'pip install python-whois'")
    sys.exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Check domain availability")
    parser.add_argument("--tld", default=".com", help="Top-level domain to check")
    parser.add_argument("--input", default="input.txt", help="Input file path")
    parser.add_argument("--output", default="free-domains.txt", help="Output file path")
    return parser.parse_args()


def read_input_file(file_path):
    prefixes, suffixes = [], []
    reading_prefixes = False

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line == '--prefixes':
                    reading_prefixes = True
                elif line == '--suffixes':
                    reading_prefixes = False
                elif line:
                    if reading_prefixes:
                        prefixes.append(line)
                    else:
                        suffixes.append(line)
    except IOError as e:
        logging.error(f"Error reading input file: {e}")
        sys.exit(1)

    return prefixes, suffixes


def generate_domains(prefixes, suffixes, tld):
    return [f"{pre}{suff}{tld}" for pre in prefixes for suff in suffixes]


def read_checked_domains(file_path):
    try:
        with open(file_path, 'r') as f:
            return set(line.strip() for line in f)
    except IOError:
        return set()


def check_domains(domains, output_file):
    with open(output_file, 'a') as f:
        for domain in domains:
            sleep(0.5)  # Basic rate limiting
            logging.info(f"Checking: {domain}")
            try:
                whois.whois(domain)
                logging.info(f"{domain} is TAKEN")
            except whois.parser.PywhoisError:
                logging.info(f"{domain} is FREE")
                f.write(f"{domain}\n")


def main():
    args = parse_arguments()
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    prefixes, suffixes = read_input_file(args.input)
    domains = generate_domains(prefixes, suffixes, args.tld)
    checked_domains = read_checked_domains(args.output)
    domains_to_check = [d for d in domains if d not in checked_domains]

    check_domains(domains_to_check, args.output)
    logging.info("DONE!")


if __name__ == "__main__":
    main()