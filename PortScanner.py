import argparse
import nmap
import os
from pystyle import Colors, Colorate


os.system('cls' if os.name == 'nt' else 'clear')

R = '\033[31m'
B = '\033[1m'
G = '\033[32m'
W = '\033[0m'
C = '\033[96m'


parser = argparse.ArgumentParser(description='Simple Port Scanner')
parser.add_argument('--scan', type=str, help='--scan ip addres')

args = parser.parse_args()

smake =print(Colorate.Vertical(Colors.cyan_to_blue, """
░██████╗███╗░░░███╗░█████╗░██╗░░██╗███████╗
██╔════╝████╗░████║██╔══██╗██║░██╔╝██╔════╝
╚█████╗░██╔████╔██║███████║█████═╝░█████╗░░
░╚═══██╗██║╚██╔╝██║██╔══██║██╔═██╗░██╔══╝░░
██████╔╝██║░╚═╝░██║██║░░██║██║░╚██╗███████╗
╚═════╝░╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝
"""))
print(Colorate.Vertical(Colors.red_to_white,B+"""
Example:
    python PortScanner.py --scan 192.168.0.1

    or

    > 192.168.0.1

"""))

def PortScanner(ip_address):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_address, arguments='-sT')
        for host in nm.all_hosts():
            print(G + f"Host : {C}%s (%s)" % (host, nm[host].hostname()))
            print(G + f"State : {C}%s" % nm[host].state())
            for proto in nm[host].all_protocols():
                print(R + "----------")
                print(G + f"Protocol : {C}%s" % proto)
                lport = list(nm[host][proto].keys())
                lport.sort()
                for port in lport:
                    print(G + f"port : {C}%s\tstate : {C}%s" % (port, nm[host][proto][port]['state'] + W))
    except KeyboardInterrupt:
        print(Colorate.Vertical(Colors.red_to_yellow, '\n'"******************************************************************"))
        print(Colorate.Vertical(Colors.red_to_yellow, '[!]Keyboard Interrupt!'))
        quit()

try:
    if args.scan:
        ip_address = args.scan
    else:
        ip_address = input(G+"> "+C)
except KeyboardInterrupt:
    print(Colorate.Vertical(Colors.red_to_yellow, '\n'"******************************************************************"))
    print(Colorate.Vertical(Colors.red_to_yellow, '[!]Keyboard Interrupt!'))
    quit()
except:
    print(Colorate.Vertical(Colors.red_to_yellow, '\n'"******************************************************************"))
    print(Colorate.Vertical(Colors.red_to_yellow,"[!]Error!"))
    quit()

PortScanner(ip_address)
