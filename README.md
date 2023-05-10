# chksslciphers

A tool to check strength of TLS ciphers used by a server.  
It parses [testssl.sh](https://github.com/drwetter/testssl.sh) output to add cipher strength information based on a provided baseline file.  

It comes with 2 baselines:
- anssi: taken from [Recommandations de sécurité relatives à TLS](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-tls/)
- ciphersuite: taken from [ciphersuite.info](https://ciphersuite.info/)

You can provide your own baseline based on the ones in the `baselines` directory, just add the file as a parameter or inside the `baselines` directory.

## Installation

Just copy the python script somewhere with the baselines directory.
No dependencies, hand-made and real dirty, no worries argument parser should arrive soon™.

## Usage

```bash
Script converting testssl.sh (https://github.com/drwetter/testssl.sh) output to rate ciphers accordingly to a baseline

Usage:
    basic: testssl.sh <url> | chksslciphers.py
    test only ciphers: testssl.sh -E <url> | chksslciphers.py ciphersuite
    ciphers + cipher order: testssl.sh -E -P <url> | chksslciphers.py anssi
    vulnerabilities + ciphers: testssl.sh -U -E <url> | chksslciphers.py ciphersuite
    full retard: testssl.sh -p -S -U -E -P <url> | chksslciphers.py anssi

Or save testssl.sh output to a file and process afterwards:
    testssl.sh -oL ssl -p -S -U -E -P <url>
    cat ssl/url.log | chksslciphers.py anssi

Parameters:
    baseline:   <ciphersuite|anssi|/path/to/file.json>
                File to compare cipher and protocol strength against
                Defaults to ciphersuite
                anssi: ANSSI guide baseline (sections A.1 & A.2)
                ciphersuite: taken from https://ciphersuite.info/
                /path/to/file.json: json file containing desired rating
```
