#!/usr/bin/env python3
# -*- coding: utf-8 -*-

######################################################################
# arpping -- Tool for the discovery of machines in local networks
# through ARP pings.
#
# Copyright (c) 2021, Scan0r
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# @Author       Scan0r
# @Date         14/02/2022
# @Version      0.1
######################################################################


######################################################################
#
# Global Imports
#
######################################################################

import argparse
import ipaddress
import pprint
from scapy.all import *


######################################################################
#
# Global Definitions
#
######################################################################

# Script config
AUTHOR = "drv"
DATE = "14/02/2022"
VERSION = "0.1"

# Global variables
DEFAULT_RETRY = 0
DEFAULT_TIMEOUT = 1
DEFAULT_VERBOSE = False

# Parser
parser = argparse.ArgumentParser(description='Tool for the discovery of machines in local networks through ARP pings.', epilog='Bye! Don\'t be evil.',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('addresses', metavar='<Target>', type=str, nargs='+', help='target IP address or network')
parser.add_argument('-r', '--retry', type=int, default=DEFAULT_RETRY, action='store', help='number of times to retry a packet send')
parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, help='number of seconds to wait for a packet response')
parser.add_argument('-v', '--verbose', default=DEFAULT_VERBOSE, action='store_true', help='enables scapy verbose mode')
parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {VERSION}')


######################################################################
#
# Auxiliary functions
#
######################################################################

def am_i_root():
    return os.geteuid() == 0


def check_address(address: str):
    ip_address_pattern = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ip_network_pattern = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/[0-9]{1,2}$')

    if bool(ip_address_pattern.match(address)):
        try:
            ipaddress.ip_address(address)
        except ValueError as ve:
            raise ve
    elif bool(ip_network_pattern.match(address)):
        try:
            ipaddress.ip_network(address)
        except ValueError as ve:
            raise ve
    else:
        raise ValueError(f"Invalid target address '{address}'")

    return True


def do_arp_ping(target: str, retry: int = DEFAULT_RETRY, timeout: int = DEFAULT_TIMEOUT, verbose: bool = DEFAULT_VERBOSE):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target, hwdst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp

    answers, unanswers = srp(pkt, retry=retry, timeout=timeout, verbose=verbose)

    print("")
    print("-" * 34)
    print(" " * 6 + "MAC Address" + " " * 2 + "IP Address")
    print("-" * 34)

    answers.summary(lambda s, r: r.sprintf("%Ether.src%  %ARP.psrc%"))
    print("")


######################################################################
#
# Main function
#
######################################################################

def main(argv: list):
    if not am_i_root():
        print("[-] You must be root to execute an ARP scan.")
        sys.exit()

    addresses = argv['addresses']
    del argv['addresses']

    for address in addresses:
        check_address(address)
        print(f"[+] Doing ARP Ping against address {address}")
        do_arp_ping(address, **argv)


######################################################################
#
# Main call
#
######################################################################

if __name__ == '__main__':
    args = parser.parse_args()
    main(vars(args))
