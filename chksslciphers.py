#!/usr/bin/env python3

# credit to https://github.com/ajanvrin/sslcompare

import sys, os, json, re
from functools import partial
import requests

CS_TPL = """
{
    "protocols": {
        "colors": {
            "obsolete": "red",
            "deprecated": "yellow",
            "supported": "green",
            "recommended": "green"
        },

        "values": {
            "SSLv2": "obsolete",
            "SSLv3": "obsolete",

            "TLS 1": "deprecated",
            "TLS 1.1": "deprecated",
            "TLS 1.2": "recommended",
            "TLS 1.3": "recommended",

            "TLSv1": "deprecated",
            "TLSv1.1": "deprecated",
            "TLSv1.2": "recommended",
            "TLSv1.3": "recommended"
        }
    },

    "ciphers": {
        "colors": {
            "insecure": "red",
            "weak": "yellow",
            "recommended": "green",
            "secure": "green",
            "unknown": "white"
        },

        "default": "unknown",

        "values": %s
    }
}
"""

def success(s):
    return f"\033[;32m{s}\033[0m"

def warning(s):
    return f"\033[;33m{s}\033[0m"

def error(s):
    return f"\033[;31m{s}\033[0m"

def bold(s):
    return f"\033[1;37m{s}\033[0m"

def color(s, c):
    if c == "green":
        return success(s)
    elif c == "yellow":
        return warning(s)
    elif c == "red":
        return error(s)
    else:
        return s

def fmt_rating(s, c):
    return color(f"[{s.upper()}]", c)

def output(s):
    sys.stdout.write(s + os.linesep)
    sys.stdout.flush()

strip_ansi = partial(re.compile(r"\x1b\[\d*m").sub, "")

deprecated_protocols = [
    "SSLv2",
    "SSLv3",
    "TLS 1",
    "TLS 1.1",
]

# TODO add --update action for ciphersuite
progname = os.path.basename(os.path.realpath(__file__))
if len(sys.argv) > 1:
    # FIXME cdegeu mais ça fonctionne
    if sys.argv[1] == '--help':
        print(f"""
Script converting testssl.sh (https://github.com/drwetter/testssl.sh) output to rate ciphers accordingly to a baseline

Usage:
    basic: testssl.sh <url> | {progname} [<baseline>]
    test only ciphers: testssl.sh -E <url> | {progname} [<baseline>]
    ciphers + cipher order: testssl.sh -E -P <url> | {progname} [<baseline>]
    vulnerabilities + ciphers: testssl.sh -U -E <url> | {progname} [<baseline>]
    full retard: testssl.sh -p -S -U -E -P <url> | {progname} [<baseline>]

Or save testssl.sh output to a file and process afterwards:
    testssl.sh -oL ssl -p -S -U -E -P <url>
    cat ssl/url.log | {progname} [<baseline>]

Parameters:
    baseline:   <ciphersuite|anssi|/path/to/file.json>
                File to compare cipher and protocol strength against
                Defaults to ciphersuite
                anssi: ANSSI guide baseline (sections A.1 & A.2)
                ciphersuite: taken from https://ciphersuite.info/
                /path/to/file.json: json file containing desired rating
        """)
        sys.exit(0)

    baseline_name = sys.argv[1]
else:
    # try to locate the installation directory to get the baselines
    baseline_name = 'ciphersuite'

baseline_file = baseline_name
if not os.path.isfile(baseline_file):
    baseline_dir = f"{os.path.dirname(os.path.realpath(__file__))}{os.sep}baselines"
    if os.path.isdir(baseline_dir):
        output(warning(f'[!] Baseline {baseline_name} not found, searching in {baseline_dir}'))
        baseline_path = f"{baseline_dir}{os.sep}{baseline_file}"
        baseline_json = baseline_path + '.json'
        if os.path.isfile(baseline_path):
            baseline_file = baseline_path
        elif os.path.isfile(baseline_json):
            baseline_file = baseline_json
        elif baseline_file == 'ciphersuite':
            output(warning(f'[!] {baseline_json} not found in directory, downlading from ciphersuite.info'))
            baseline_file = baseline_json
            baseline = {}
            # verify=False si proxy ou what
            # requests.packages.urllib3.disable_warnings()
            resp = requests.get('https://ciphersuite.info/api/cs/')
            if resp.status_code == 200:
                for cs in resp.json()['ciphersuites']:
                    # only one items though
                    for cipher, infos in cs.items():
                        baseline[cipher] = infos['security']

                with open(baseline_file, 'w') as o:
                    o.write(CS_TPL % json.dumps(baseline))
                    output(success(f'[+] download complete'))
            else:
                output(error(f'[-] download failed with status {resp.status_code}'))
                sys.exit(1)
        else:
            output(error(f'[-] Baseline file {baseline_file} not found in {baseline_dir}'))
            sys.exit(1)
    else:
        output(error(f'[-] Baseline file {baseline_file} not found'))
        sys.exit(1)

output(success(f'[+] Found baseline {baseline_name} at {baseline_file}'))
with open(baseline_file) as f:
    baseline = json.loads(f.read().rstrip())

baseline_dir = f"{os.path.dirname(os.path.realpath(__file__))}{os.sep}baseline"
if os.path.isdir(baseline_dir):
    baseline_path = f"{baseline_dir}{os.sep}{baseline_file}"
    if os.path.isfile(baseline_path):
        baseline_file = baseline_path
    elif os.path.isfile(baseline_path + '.json'):
        baseline_file = baseline_path + '.json'
    elif baseline_file == 'ciphersuite':
        sys.stdout.write(warning(f'[-] {baseline_file} not found in directory, downlading from ciphersuite.info... '))
        sys.stdout.flush()
        baseline = {}
        resp = requests.get('https://ciphersuite.info/api/cs/')
        if resp.status_code == 200:
            for cs in resp.json()['ciphersuites']:
                # only one items though
                for cipher, infos in cs.items():
                    baseline[cipher] = infos['security']

            with open(baseline_file, 'w') as o:
                o.write(CS_TPL % json.dumps(baseline))
                output(success('[OK] download complete'))


# TODO add --live option to fetch from /cs/<iana_name> directly and not cache
if not os.path.isfile(baseline_file):
    sys.stdout.write(warning(f'[-] {baseline_file} not found in directory, downlading from ciphersuite.info... '))
    sys.stdout.flush()
    baseline = {}
    resp = requests.get('https://ciphersuite.info/api/cs/')
    if resp.status_code == 200:
        for cs in resp.json()['ciphersuites']:
            # only one items though
            for cipher, infos in cs.items():
                baseline[cipher] = infos['security']

        with open(baseline_file, 'w') as o:
            o.write(CS_TPL % json.dumps(baseline))
            output(success('[OK] download complete'))





output(success(f'[+] Loaded {baseline_file} ciphers'))

current_protocol = None
raw_protocole = ""
testing_ciphers = False
printed_proto_header = False

for raw in sys.stdin:
    line = raw.rstrip(os.linesep)

    if testing_ciphers:

        if "Cipher Suite Name (IANA/RFC)" in line:
            output(f" {'Cipher Suite Name (IANA/RFC)':50} {'Evaluation':20}")
        
        elif len(line) > 0 and strip_ansi(line).split('(')[0].rstrip() in baseline['protocols']['values']:
            current_protocol = strip_ansi(line).split('(')[0].rstrip()
            # msg_protocol = strip_ansi(line).split('(')[1].split(')')[0]
            raw_protocol = line
            printed_proto_header = False

        elif current_protocol is not None:
            if line == " - ": # protocol not offered by server

                if current_protocol in deprecated_protocols:
                    hdr = f"{raw_protocol:<58} {success('[NOT OFFERED]'):<20}"
                else:
                    hdr = f"{raw_protocol:<58} {'[NOT OFFERED]':<20}"
                output('')
                output(hdr)
                printed_proto_header = True
            elif line == "":
                # end of ciphers
                output('')
                testing_ciphers = False
            else:
                if printed_proto_header == False:
                    rating = fmt_rating(
                        baseline['protocols']['values'][current_protocol],
                        baseline['protocols']['colors'][baseline['protocols']['values'][current_protocol]]
                    )
                    output(f"{os.linesep}{raw_protocol:<58} {rating:<20}")
                    printed_proto_header = True
                
                l = line.split()
                cipher_iana = l[-1]
                cipher_openssl = l[1]
                
                if cipher_iana not in baseline['ciphers']['values']:
                    rating = fmt_rating(
                        baseline['ciphers']['values']['default'],
                        baseline['ciphers']['colors'][baseline['ciphers']['values']['default']]
                    )
                    output(f" {cipher_iana:<50} {rating:<20}")
                else:
                    try:
                        rating = fmt_rating(
                            baseline['ciphers']['values'][cipher_iana],
                            baseline['ciphers']['colors'][baseline['ciphers']['values'][cipher_iana]]
                        )
                        output(f' {cipher_iana:<50} {rating:<30}')
                    except KeyError:
                        # missing color
                        output(f" {cipher_iana:<50} [{baseline['ciphers']['values'][cipher_iana].upper()}]")

        else:
            sys.stdout.write(raw)
            sys.stdout.flush()

    elif "Testing ciphers per protocol" in line or "Testing server's cipher preferences" in line:
        testing_ciphers = True
        output(line)
    
    else:
        sys.stdout.write(raw)
        sys.stdout.flush()

