# Domainfinder
Domainfinder is a Python script that generates domain names by combining prefixes and suffixes, then checks their availability. It's a useful tool for anyone looking to find unique domain names for their projects.

## Features

Generates domain names from user-defined prefixes and suffixes
* Checks domain availability using WHOIS lookup
* Saves free domains to a file for easy reference
* Supports custom top-level domains (TLDs)
* Command-line interface for easy customization

## Requirements

Python 3.6+
python-whois module

## Installation

Clone the repository:
1. `git clone https://github.com/caspii/domainfinder.git`
2. `cd domainfinder`
3. Install the required module:
`pip install python-whois`

## Usage

Edit the `input.txt` file:

* Add your desired prefixes under the --prefixes section
* Add your desired suffixes under the --suffixes section


Run the script:
`python find.py`

Optional: Customize the script execution with command-line arguments:

`python find.py --tld .com --input custom_input.txt --output available_domains.txt`

## Example

If your `input.txt` contains:

```
--prefixes
ilove
--suffixes
money
myself
```
The script will check the availability of:

* ilovemoney.com
* ilovemyself.com

## Output

The script will display the status of each domain check in the console.
Free domains will be saved to free-domains.txt (or your specified output file).

## Advanced Usage
You can customize the script's behavior using command-line arguments:

```
--tld: Specify a custom top-level domain (default: .com)
--input: Use a custom input file (default: input.txt)
--output: Specify a custom output file for free domains (default: free-domains.txt)
```

Example:
`python find.py --tld .org --input my_inputs.txt --output available_org_domains.txt`

## Additional Resources
For more information on domain finding strategies, check out this blog post: [Finding a Domain](http://casparwre.de/blog/finding-a-domain/)