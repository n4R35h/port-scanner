#!/usr/bin/python

import gettext
import optparse
import sys
import socket
import time
import subprocess
from datetime import datetime
import output_messages
import basedefs

_ = lambda m: gettext.dgettext(message=m, domain='myTool')


class Status:
    """
    Exit statuses
    """
    OK = 0
    MISSING_OPTION = 1
    KEYBOARD_INTERRUPT = 2
    CANNOT_CONNECT = 3
    RANGE_ERROR = 4


class PortScanner():
    """
    Port scanner class

    Parameters:
        dst_ip_addr - target ip address
        interval - time interval between each scan
        protocol_type - protocol type to scan
        type - scan type
        ports - ports to scan (default defined in get_args())
    """

    def __init__(self,
                 dst_ip_addr,
                 interval,
                 protocol_type,
                 type,
                 ports):

        self.dst_ip_address = dst_ip_addr
        self.interval = interval
        self.protocol_type = protocol_type.upper()
        self.ports = ports
        self.type = type

    def port_scanner(self):
        """
        Scans the ports of the given ip address

        """
        _socket_type = None
        _socket_family = socket.AF_INET
        _ports = [self.ports]
        _protocol = output_messages.CANT_RECOGNIZE

        # Validate socket
        if self.protocol_type == 'TCP':
            _socket_type = socket.SOCK_STREAM
        if self.protocol_type == 'UDP':
            _socket_type = socket.SOCK_DGRAM

        # Validate ports
        if ',' in self.ports:
            _ports = self.ports.split(',')
        if '-' in self.ports:
            __ports = self.ports.replace('-', ',').split(',')
            if not int(__ports[0]) < int(__ports[1]):
                print(
                    _(output_messages.RANGE_ERROR.format(
                        __ports[0],
                        __ports[1]
                    ))
                )
                sys.exit(Status.RANGE_ERROR)

            _ports = range(int(__ports[0]), int(__ports[1]))
            _ports.append(int(__ports[1]))

        print(
            _(output_messages.SCANNING.format(
                self.dst_ip_address
            ))
        )

        # Start scan time
        _t1 = datetime.now()

        try:
            for port in _ports:
                if port in basedefs.ports_mapping:
                   _protocol = basedefs.ports_mapping[port].split(',')[0]
                sock = socket.socket(_socket_family, _socket_type)
                result = sock.connect_ex((self.dst_ip_address, int(port)))
                if result == 0:
                    print(
                        _(output_messages.OPEN_PORT.format(
                            port,
                            _protocol
                        ))
                    )
                sock.close()
                time.sleep(self.interval * 0.001)

        except KeyboardInterrupt:
            print(
                _(output_messages.KEYBOARD_INTERRUPT)
            )
            sys.exit(Status.KEYBOARD_INTERRUPT)

        except socket.error:
            print(
                _(output_messages.CANNOT_CONNECT.format(
                    self.dst_ip_address,
                ))
            )
            sys.exit(Status.CANNOT_CONNECT)

        # End scan time
        _t2 = datetime.now()
        _total = _t2 - _t1
        print(
            _(output_messages.SCANNING_COMPLETED.format(
                _total
            ))
        )


def get_args():
    """
    Command line options
    """
    parser = optparse.OptionParser(description='Reads user command line args.')
    parser.add_option('--ip', dest='ip',
                      help='target ip address')
    parser.add_option('--time-interval', '-t', dest='time_interval',
                      type='int', default='2000',
                      help='time interval between each scan in milliseconds')
    parser.add_option('--protocol-type', dest='protocol_type',
                      help='protocol type [UDP/TCP/ICMP]')
    parser.add_option('--port', '-p', dest='ports',
                      help='ports [can be range : -p 22-54,'
                           'can be single port : -p 80, can be combination : -p 80,43,23,125]')
    parser.add_option('--type', dest='scan_type',
                      default='full',
                      help='scan type [full,stealth,fin,ack]')
    parser.add_option('--banner_grabber', '-b', dest='banner_grabber', action='store_true',
                      help='bannerGrabber status (Should work only for TCP)')

    return parser.parse_args()


def main():
    (options, args) = get_args()

    if not options.ip:
        print(
            _(output_messages.MISSING_OPTION.format(
                '--ip',
            ))
        )

        sys.exit(Status.MISSING_OPTION)

    if not options.protocol_type:
        print(
            _(output_messages.MISSING_OPTION.format(
                '--protocol-type'
            ))
        )
        sys.exit(Status.MISSING_OPTION)

    if not options.ports:
        print(
            _(output_messages.MISSING_OPTION.format(
                '--port | -p'
            ))
        )
        sys.exit(Status.MISSING_OPTION)

    port_scanner = PortScanner(options.ip,
                               options.time_interval,
                               options.protocol_type,
                               options.scan_type,
                               options.ports)
    port_scanner.port_scanner()

if __name__ == '__main__':
    main()