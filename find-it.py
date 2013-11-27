#!/usr/bin/env python
import subprocess
import time

suffixes = []
prefixes = []

readingSuffixes = False
readingPrefixes = False

# 1. Get prefixes and suffixes and put them into arrays
f = open('input.txt')
for l in f:
	line = l.strip()

	if line == '--prefixes':
		readingSuffixes = False
		readingPrefixes = True
		continue
	elif line == '--suffixes':
		readingSuffixes = True
		readingPrefixes = False
		continue
	elif not line:
		continue # Ignore empty lines
	
	if readingSuffixes:
		suffixes.append(line)
	if readingPrefixes:
		prefixes.append(line)
	
f.close()

# 2. create list of domains from prefixes and suffixes
domains	=[]
for pre in prefixes:
	for suff in suffixes:
		domains.append( pre + suff + ".it")


# 3. Get list of domains that have aleady found to be free
checkeddomains= [line.strip() for line in open('checked-domains.txt')] # Strip out newlines too

# 4. Remove domains that were already found to be free
for remove in checkeddomains:
	try:
		domains.remove(remove)
	except ValueError:
		pass # Ignore exceptions


# 5. Check list of domains and write to file
check="Status:             AVAILABLE"
for domain in domains:
	print(' Checking: ' + domain), # Comma means no newline is printed	
	result = subprocess.check_output(["whois", domain])
	f = open('checked-domains.txt', 'a')
	f.write(domain + '\n')
	f.close()
	time.sleep(3) # Sleep for x seconds
	if check in result:
		print('\tFREE')
		f = open('free-domains.txt', 'a')
		f.write(domain + '\n')
		f.close()
	else:
		print('\tTAKEN')

	
print("DONE!")
