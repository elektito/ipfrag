#!/usr/bin/env python

# suppress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import RawPcapReader, PcapWriter, IP, Ether, defragment

import argparse

def main():
    parser = argparse.ArgumentParser(
        description='Defragments the IPv4 packets in the given PCAP file '
        'and writes the results to another file.')
    parser.add_argument('input_file')
    parser.add_argument('output_file')

    args = parser.parse_args()

    fragments = []
    reader = RawPcapReader(args.input_file)
    writer = PcapWriter(args.output_file, append=False, sync=True)
    for pkt_data in reader:
        p = Ether(pkt_data[0])
        if not isinstance(p[1], IP):
            writer.write(p)
            continue

        if p[IP].flags & 1 == 0 and p[IP].frag == 0:
            writer.write(p)
            continue

        fragments += p
        fragments = defragment(fragments)
        defragged = []
        for f in fragments:
            if f[IP].flags & 1 == 0 and f[IP].frag == 0:
                defragged.append(f)
        fragments = [f for f in fragments if f not in defragged]
        for df in defragged:
            print 'boo'
            writer.write(df)

if __name__ == '__main__':
    main()
