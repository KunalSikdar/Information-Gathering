from time import process_time_ns

import whois
import dns.resolver
import shodan
import requests
import sys
import argparse
import socket

from Simple_port_scanner_using_scapy import result

argparse = argparse.ArgumentParser(description = "This a basic information gathering tool..", usage = "python3 information_gathering.py -d DOMAIN [-S IP]")
argparse.add_argument("-d", "--domain", help = "Enter the domain name for footprinting..", required = True)
argparse.add_argument("-s", "--shodan", help = "Enter the ip for shodan search..")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan

print("[+] Getting whois info..")
try:
    py = whois.query(domain)
    print("[+] Whois info found..")
    print("Name : {}".format(py.name))
    print("Register : {}".format(py.registrar))
    print("Creation Date : {}".format(py.creation_date))
    print("Expiration Date : {}".format(py.expiration_date))
    print("Registrant : {}".format(py.registrant))
    print("Registrant Country : {}".format(py.registrant_country))
except:
    pass


print("[+] Getting DNS info..")
try:
    for a in dns.resolver.resolve(domain,'A'):
        print("[+] A Record : {}".format(a.to_text()))
    for ns in dns.resolver.resolve(domain,'NS'):
        print("[+] NS Record : {}".format(ns.to_text()))
    for mx in dns.resolver.resolve(domain,'MX'):
        print("[+] MX Record : {}".format(mx.to_text()))
    for txt in dns.resolver.resolve(domain,'TXT'):
        print("[+] TXT Record : {}".format(txt.to_text()))
except:
    pass

print("[+] Getting geo-location info..")
try:
    reponse = requests.Request("Get","https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print("[+] Country : {}".format(reponse['country_name']))
    print("[+] Lattitude : {}".format(reponse['lattitude']))
    print("[+] Longitude : {}".format(reponse['longitude']))
    print("[+] City : {}".format(reponse['city']))
    print("[+] State : {}".format(reponse['State']))
except:
    pass

if ip:
    print("[+] Getting shodan info..")
    api = shodan.Shodan("API KEY")
    try:
        results = api.search(ip)
        print("[+] Result found : {}".format(results['total']))
        for result in results['matches']:
            print("[+] IP : {}".format(result['ip_str']))
            print("[+] Data : {}".format(result['data']))
            print()
    except:
        print("[+] Shodan search error..!")