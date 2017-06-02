Domainfinder
============
This is a Python script for generating domain names by taking a list of prefixes
and joining then with a list of suffixes. It then checks if they are free and
writes the results to a file.

For example, if you only have the prefix **ilove** and the two suffixes, **money** and **myself**, then the script will check if the following domains are free:
```
ilovemoney.com
iloveymyself.com
```
Requires the ``python-whois`` module to be installed.

# Howto
1. Checkout the code: `git clone git@github.com:caspii/domainfinder.git`

2. Create your own inputs:
   * Open the file `input.txt`. You’ll see that it contains a section titled _–prefixes_ and one called _–suffixes_.
   * Simply edit these sections as you see fit, taking care not to delete the actual section titles.

3. Run the command `/find.py` and the script will take the inputs you specified and begin checking which domains are free.

4. You’ll see the output as each domain is checked and the result in your console. All free domains are saved into a file called `free-domains.txt` for later perusal.

Also see here: http://casparwre.de/blog/finding-a-domain/
