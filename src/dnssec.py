import urllib.request
import re
import dns.resolver
import dns.rdatatype
import csv
import os.path
import json
import argparse

parser = argparse.ArgumentParser(
    prog='DNSSEC',
    description='Evaluates the presence of DNSSEC DS record for domain names from IANA root DB or public suffix list.')

url_public_suffix = 'https://publicsuffix.org/list/public_suffix_list.dat'
url_iana_tlds = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'


parser.add_argument('-s', '--source', choices=['publicsuffix', 'iana'], type=str.lower, required=True,
                    help='Source of domain names: "publicsuffix" for Public Suffix List or "iana" for IANA TLDs')
parser.add_argument('-p', '--path', type=str, default='.',
                    help='Path to save the output files (default: current directory)')
parser.add_argument('-m', '--max', type=int, help='Maximum number of domain names to process', required=False)
args = parser.parse_args()

if args.source == 'publicsuffix':
    url = url_public_suffix
    filename = 'public_suffix_list'
elif args.source == 'iana':
    url = url_iana_tlds
    filename = 'iana_tlds'
path = args.path
max = args.max

resolver = dns.resolver.Resolver()
resolver.nameservers = [
    # Google 
    "8.8.8.8",
    "8.8.4.4",

    # Quad9
    "9.9.9.9",
    "149.112.112.112",

    # OpenDNS Home
    "208.67.222.222",
    "208.67.220.220",
            
    # Cloudflare
    "1.1.1.1",
    "1.0.0.1",

    # Verisign Public DNS
    "64.6.64.6",
    "64.6.65.6"
]
    
def fetch_domain_names(url: str) -> set:
    headers = {
        'User-Agent': 'DPL.DnsSec/1.0 (https://github.com/darkpeaklabs/DNSSEC)'
    }

    names = set()
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request) as response:
        for line in response:
            name = line.strip().decode('utf-8').lower()
            match = re.match(r'^[a-z0-9]', name)
            if match:
                names.add(name)
    return names

def evaluate_domain_name(name: str):

    result = {
        'name': name.encode('idna').decode('ascii'),
        'dnssec': None,
        'dnskey': None,
        'error': None
    }

    try:
        answers = resolver.resolve(name, dns.rdatatype.DS, raise_on_no_answer=True)
        result['dnssec'] = False
        for answer in answers:
            if answer.rdtype == dns.rdatatype.DS:
                result['dnssec'] = True
                result['dnskey'] = answer.digest.hex()
    except dns.resolver.NoAnswer:
        result['dnssec'] = False
    except Exception as e:
        result['error'] = str(e)
    return result

domain_names = fetch_domain_names(url)

print(f"Fetched {len(domain_names)} domain names from {url}.")
total = len(domain_names)
count = 0
results = []
header = True

filepath = os.path.join(path, f'{filename}.csv')
with open(filepath, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['name', 'dnssec', 'dnskey', 'error'])
    writer.writeheader()
    for name in domain_names:
        count += 1
        print(f"Processing {count}/{total}: {name}")
        result = evaluate_domain_name(name)
        writer.writerow(result)
        results.append(result)
        if max and count >= max:
            print(f"Reached maximum of {max} domain names, stopping.")
            break

print(f"Results written to CSV {filepath}")
print(f"Processed {count} domain names.")

filepath = os.path.join(path, f'{filename}.json')
with open(filepath, 'w') as jsonfile:
    json.dump(results, jsonfile, indent=4)
print(f"Results written to JSON {filepath}")