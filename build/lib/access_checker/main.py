#! /usr/bin/python3
import argparse
from access_checker.acl_parser import cisco_acl


def main():
    parser = argparse.ArgumentParser(description='Checking if access is allowed')
    parser.add_argument('-sip', '--srcip', type=str, required=True, help='Source IP or subnet, example: 10.1.1.0/28')
    parser.add_argument('-dip', '--destip', type=str, required=True,
                        help='Destination IP or subnet, example: 10.0.0.0/8')
    parser.add_argument('-sport', '--srcport', type=str, required=True, help='Source port, example: 2000')
    parser.add_argument('-dport', '--dstport', type=int, required=True, help='Destination port, example: 80')
    parser.add_argument('-p', '--protocol', type=str, required=True, help='Protocol, example: tcp')
    parser.add_argument('-f', '--file', type=str, required=True,
                        help='File path, example: /Users/test/Desktop/test.acl')
    args = parser.parse_args()

    if '.acl' in args.file:
        cisco_acl(args.srcip, args.destip, args.srcport, args.dstport, args.protocol, args.file)


if __name__ == "__main__":
    main()
