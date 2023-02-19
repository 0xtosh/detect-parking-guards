#!/usr/bin/python3
import os
from scapy.all import *
import time

parking_guys = ["00:11:22:33:44:55", "66:77:88:99:AA:BB"]
parking_ssids_probe = ["Qpark G4S", "Qpark pms_5G"]

def handle_probe_request(pkt):
    if pkt.haslayer(Dot11):
 if pkt.type == 0 and pkt.subtype == 4 and (pkt.addr2 in parking_guys or pkt.info.decode() in parking_ssid_probe):
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"{current_time}: Parking guy is here!")
            os.system("./flash_dirigera_ikea_lights_10x.sh")

sniff(prn=handle_probe_request, iface="wlan0", store=0)
