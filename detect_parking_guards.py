#!/usr/bin/python3
import os
from scapy.all import *
import time

parking_guys = ["00:11:22:33:44:55", "66:77:88:99:AA:BB"]
parking_ssid_probe = ["Qpark G4S", "Qpark pms_5G"]
ssid_probe_file = "parking_ssid_probe.txt"

def handle_probe_request(pkt):
    global parking_ssid_probe
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 4 and (pkt.addr2 in parking_guys or pkt.info.decode() in parking_ssid_probe):
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"{current_time}: Parking guy is here!")
            os.system("./flash_dirigera_ikea_lights_10x.sh")

            # Check if the MAC address is already in the list of known parking guys
            if pkt.addr2 not in parking_guys:
                print(f"New MAC address detected: {pkt.addr2}")
                parking_guys.append(pkt.addr2)

            # Check if the SSID probe is a new value
            if pkt.info.decode() not in parking_ssid_probe:
                print(f"New SSID probe detected: {pkt.info.decode()}")
                parking_ssid_probe.append(pkt.info.decode())
                with open(ssid_probe_file, "w") as f:
                    for ssid in parking_ssid_probe:
                        f.write(f"{ssid}\n")

sniff(prn=handle_probe_request, iface="wlan0", store=0)
