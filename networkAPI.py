from fastapi import FastAPI
from scapy.layers.I2 import ARP, Ether
from scapy.sendrecv import srp 

app = FastAPI()

def network_scan(ip_range):
    """
    Scans the network and returns a list of connected devices.
    :param ip_range: The IP range to scan (e.g, '192.168.1.1/24)
    """
    arp_request = ARP(pdst=ip-range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})
    return devices

@app.get("/scan")
def scan_network(ip_range: str="192.168.1.1/24"):
    """API endpoint to scan the netwrok adn return connected devices"""
    devices = network_scan(ip_range)
    return {"devices": devices}





