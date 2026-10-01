#!/usr/bin/env python3
"""
LoRaWAN Frame Extractor for ChirpStack Simulator PCAPs
Extracts raw LoRaWAN frames (Join-Requests, Join-Accepts, Data) from ChirpStack
MQTT/Protobuf captures and writes them to a native LoRaWAN PCAP (LoRaTap link type 270).

Usage:
    python3 extract_lorawan.py <input_mqtt.pcap> <output_lorawan.pcap>
"""

import sys
import struct
import subprocess
from datetime import datetime, timezone

def convert(input_pcap, output_pcap):
    # Standard LoRaTap header (v0, 15 bytes, syncword 0x34 tells Wireshark this is LoRaWAN)
    # Freq: 868.1 MHz, BW: 125 kHz, SF7, Syncword: 0x34 (LoRaWAN)
    loratap_hdr = bytes([0, 0, 0, 15, 0x33, 0xbf, 0xd3, 0xa0, 1, 7, 0x50, 0x50, 0x50, 0x20, 0x34])
    
    proc = subprocess.Popen(
        ['text2pcap', '-l', '270', '-t', '%Y-%m-%d %H:%M:%S.', '-', output_pcap],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    count = 0
    with open(input_pcap, 'rb') as f:
        f.read(24) # PCAP global header
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack('<IIII', pkt_hdr)
            data = f.read(incl_len)
            
            if b'eu868/gateway/' in data:
                idx = data.find(b'eu868/gateway/')
                if idx > 2:
                    topic_len = struct.unpack('>H', data[idx-2:idx])[0]
                    topic = data[idx:idx+topic_len].decode('latin1', errors='ignore')
                    rest = data[idx+topic_len:]
                    
                    phy = None
                    if '/event/up' in topic and len(rest) > 2 and rest[0] == 0x0a:
                        phy_len = rest[1]
                        phy = rest[2:2+phy_len]
                    elif '/command/down' in topic:
                        pos = rest.find(b'\x0a')
                        if pos != -1 and pos + 2 < len(rest):
                            plen = rest[pos+1]
                            if 12 <= plen <= 60 and pos + 2 + plen <= len(rest):
                                phy = rest[pos+2:pos+2+plen]
                    
                    if phy and len(phy) >= 12:
                        count += 1
                        packet_bytes = loratap_hdr + phy
                        hex_line = '000000 ' + ' '.join(f'{b:02x}' for b in packet_bytes) + '\n'
                        dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
                        ts_str = dt.strftime('%Y-%m-%d %H:%M:%S') + f'.{ts_usec:06d} '
                        proc.stdin.write(ts_str + hex_line)

    proc.stdin.close()
    proc.communicate()
    print(f"Extracted {count} LoRaWAN frames into '{output_pcap}'.")

if __name__ == '__main__':
    in_file = sys.argv[1] if len(sys.argv) > 1 else 'chirpstack_traffic.pcap'
    out_file = sys.argv[2] if len(sys.argv) > 2 else 'lorawan_traffic.pcap'
    convert(in_file, out_file)
