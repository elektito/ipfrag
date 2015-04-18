#!/usr/bin/env python

# suppress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import RawPcapReader, PcapWriter, IP, Ether, fragment

import argparse

def main():
    parser = argparse.ArgumentParser(
        description='Fragments the IPv4 packets in the given PCAP file '
        'and writes the results to another file.')
    parser.add_argument('input_file')
    parser.add_argument('output_file')
    parser.add_argument(
        '--fragment-size', '-s', type=int, default=500,
        help='Fragment size. Packets larger than this are fragmented '
        'if their df flag is not set. Defaults to 500.')

    args = parser.parse_args()

    reader = RawPcapReader(args.input_file)
    writer = PcapWriter(args.output_file, append=False, sync=True)
    for pkt_data in reader:
        p = Ether(pkt_data[0])
        if isinstance(p[1], IP) and len(p[2]) > args.fragment_size and p[1].flags & 2 != 0:
            p = fragment(p, args.fragment_size)
            print 'Fragmented packet into {} fragments.'.format(len(p))

        writer.write(p)

if __name__ == '__main__':
    main()
