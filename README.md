# Incident-Alarm

Written By: Katherine Epifanio
Date: 3-10-21

Purpose:

        The program alarm.py analyzes a live stream of network packets
        or a set of PCAPs for the following incidents:

            - NULL scan
            - FIN scan
            - Xmas scan
            - Usernames & passwords sent in-the-clear via HTTP Basic
              Authentication, FTP, and IMAP
            - Nikto scan
            - Someone scanning for Server Message Block (SMB) protocol

        If an incident is detected, a message prints to standard output
        in the following form:

            ALERT #{incident_number}: #{incident} is detected
            from #{source IP address} (#{protocol or port number}) (#{payload})!

        The program does not save any packets or detected incidents.


Dependencies:

        - python3
        - scapy
        - root or admin access


Compiling:

        Kali Linux:     sudo python3 alarm.py [options]


Usage:

        alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]

        Default behavior:
          If no arguments are provided, the program sniffs on network
          interface eth0.

        Optional arguments:
          -h, --help    show this help message and exit
          -i INTERFACE  Network interface to sniff on
          -r PCAPFILE   A PCAP file to read

        To quit, Control-C.


Ackowledgements:

        https://pymotw.com/2/socket/addressing.html

        https://wiki.sans.blue/Tools/pdfs/ScapyCheatSheet_v0.2.pdf

        https://scapy.readthedocs.io/en/latest/


Potential Improvements:

        - While performing checks for username and password credentials
          sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
          protocols, I implemented each type of check separately (thinking
          that each type of check would look fundamentally different between
          protocols). It ended up being the case that all three protocol
          types took a fairly similar approach, so there is definitely room
          for improving modularity.

        - I have not done any profiling for time complexity yet. Current
          runtime is reasonable, but certain pcap files are noticeably slower
          than others. Not sure if this has been a function of pcap file length
          or if certain incidents are taking longer to comb through than others
          (or both) - something to look into.

        - To identify scans for a Server Message Block (SMB), alarm.py
          checks for packets with a destination port of either 445 or 139.
          I'm not clear on whether scanning for both ports is necessary
          or functionally correct.
