#!/usr/bin/env python
from time import sleep
import sys
try:
	import whois
except ImportError:
	print("ERROR: This script requires the python-whois module to run.")
	print("   You can install it via 'pip install python-whois'")
	sys.exit(0)

# Change top-level domain to check here
TLD = '.com'

# 1. Get prefixes and suffixes from input.txt
suffixes = []
prefixes = []
readingPrefixes = False
f = open('input.txt')
for l in f:
	line = l.strip()
	if line == '--prefixes':
		readingPrefixes = True
		continue
	elif line == '--suffixes':
		readingPrefixes = False
		continue
	elif not line:
		continue # Ignore empty lines
	if readingPrefixes:
		prefixes.append(line)
	else:
		suffixes.append(line)
f.close()

# 2. create list of domains from prefixes and suffixes
domains	=[]
for pre in prefixes:
	for suff in suffixes:
		domains.append( pre + suff + TLD)

# 3. Get list of domains that have aleady found to be free and removed them
checkeddomains= [line.strip() for line in open('free-domains.txt')] # Strip out newlines too
for remove in checkeddomains:
	try:
		domains.remove(remove)
	except ValueError:
		pass # Ignore exceptions

# 4. Check list of domains and write to file
for domain in domains:
	sleep(0.5) # Too many requests lead to incorrect responses
	print(' Checking: ' + domain), # Comma means no newline is printed
	try:
		w = whois.whois(domain)
		print('\tTAKEN')
	except whois.parser.PywhoisError:
		# Exception means that the domain is free
		print('\tFREE')
		f = open('free-domains.txt', 'a')
		f.write(domain + '\n')
		f.close()
print("DONE!")
