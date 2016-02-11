#!/usr/bin/env python
import subprocess
import sys
import shutil

# Check whether whois command is available
try:
	subprocess.check_output(["whois","google.com"])
except OSError:
	print('ERROR: whois command not found. \n\tIs it installed? Are you using Linux?')
	sys.exit()

suffixes = []
prefixes = []

readingPrefixes = False

# 1. Get prefixes and suffixes and put them into arrays
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
		domains.append( pre + suff + ".io")

# 3. Get list of domains that have aleady found to be free and removed them
checkeddomains= [line.strip() for line in open('free-domains.txt')] # Strip out newlines too
for remove in checkeddomains:
	try:
		domains.remove(remove)
	except ValueError:
		pass # Ignore exceptions


# 4. Check list of domains and write to file
for domain in domains:
	print(' Checking: ' + domain), # Comma means no newline is printed
	try:
		result = subprocess.check_output(["whois", domain])
		print('\tTAKEN')
	except subprocess.CalledProcessError:
		f = open('free-domains.txt', 'r+')
		# Exception means that the domain is free
		print('\tFREE')
		f.write(domain + '\n')
		f.close()
print("DONE!")
