#!/usr/bin/python3
from scapy.all import *
import argparse
import os
import socket
import pcapy
import base64

# Declare Constants
NULL = ""
XMAS = "FPU"
FIN = "F"
incident_num = 0
user = None
pwd = None
pwd_loop = 0

# Define potential protocol values
protocols = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}

######## SCAN DETECTION FUNCTIONS ########
def print_scan_alert(incident, src_port, proto_num):
    global incident_num
    incident_num += 1
    print("ALERT #{0}: {1} is detected from {2} ({3})!" .format(incident_num,
                                   incident, src_port, protocols[proto_num]))

def check_scan(packet):
    if packet.sprintf('%TCP.flags%') == NULL:
        print_scan_alert("Null scan", packet[IP].src, packet.proto)
    elif packet.sprintf('%TCP.flags%') == XMAS:
        print_scan_alert("Xmas scan", packet[IP].src, packet.proto)
    elif packet.sprintf('%TCP.flags%') == FIN:
        print_scan_alert("Fin scan", packet[IP].src, packet.proto)
    elif packet[TCP].dport == 445 or packet[TCP].dport == 139:
        print_scan_alert("SMB scan", packet[IP].src, packet.proto)

def nikto_check(packet):
    pkt_data = str(packet)
    # Nikto scan check
    if "nikto" in pkt_data.lower():
        print_scan_alert("Nikto scan", packet[IP].src, packet.proto)

######## USERNAME & PASSWORD DETECTION ########
def print_credentials(packet, user, pwd, proto_num):
    global incident_num
    incident_num += 1
    print("ALERT #{0}: Usernames and passwords sent in-the-clear ({1}) (username:{2}, password:{3})"
                                            .format(incident_num, protocols[proto_num], user, pwd));

def http_credentials(packet):
    pkt_data = str(packet)
    global pwd_loop
    if pwd_loop == 0:
        if "Authorization: Basic" in pkt_data:
            start = pkt_data.find("Basic") + 6
            end = pkt_data.find("\\r", start)
            usrpass = pkt_data[start: end]
            decoded = base64.b64decode(usrpass).decode('UTF-8')
            divider = decoded.find(":")
            user = decoded[:divider]
            pwd = decoded[divider + 1: end]
            print_credentials(packet, user, pwd, packet.proto)
            pwd_loop += 1
    else:
        pwd_loop = 0

def ftp_credentials(packet):
    pkt_data = str(packet)
    global user
    global pwd

    if "USER" in pkt_data:
        user_start = pkt_data.find("USER") + 5
        user_end = pkt_data.find("\\r", user_start)
        user = pkt_data[user_start: user_end]

    if "PASS" in pkt_data:
        pwd_start = pkt_data.find("PASS") + 5
        pwd_end = pkt_data.find("\\r", pwd_start)
        pwd = pkt_data[pwd_start: pwd_end]

    return(user, pwd)

def imap_credentials(packet):
    pkt_data = str(packet)
    global pwd_loop
    if pwd_loop == 0:
        if "LOGIN" in pkt_data:
            start = pkt_data.find("LOGIN") + 6
            end = pkt_data.find("\\r", start)
            line = pkt_data[start: end]
            credentials = line.split()
            user = credentials[0]
            pwd = credentials[1]
            pwd = pwd[1: ]
            pwd = pwd[: -1]
            print_credentials(packet, user, pwd, packet.proto)
            pwd_loop += 1
    else:
        pwd_loop = 0

def pwd_check(packet):
    global user
    global pwd

    # Credentials sent in-the-clear via TCP, HTTP, or IMAP
    if packet[TCP].dport == 21:
        user, pwd = ftp_credentials(packet)
        if user != None and pwd != None:
            print_credentials(packet, user, pwd, packet.proto)
            user = None
            pwd = None
    elif packet[TCP].dport == 80:
        http_credentials(packet)
    elif packet[TCP].dport == 143:
        imap_credentials(packet)

    return

######## RUN SCANNER ########
def packetcallback(packet):
    # Check for NULL, XMAS, FIN, and SMB scans
    try:
        check_scan(packet)
    except:
        pass

    # Check for usernames & passwords
    try:
        pwd_check(packet)
    except:
        pass

    # Check for Nikto scans
    try:
        nikto_check(packet)
    except:
        pass


parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
