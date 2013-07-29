#!/usr/bin/python

import gettext
import re
import optparse
import sys
import socket
import time
from datetime import datetime
import output_messages
import basedefs
try:
    import iptools
except ImportError:
    print(
        _(output_messages.CANT_IMPORT.format(
            'iptools'
        ))
    )

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
    IP_ERROR = 5


def get_args():
    """
    Command line options
    """
    parser = optparse.OptionParser(description='Reads user command line args.')
    parser.add_option('--ip',
                      dest='ip',
                      help='target ip address')
    parser.add_option('--time-interval', '-t',
                      dest='time_interval',
                      type='int',
                      default='2000',
                      help='time interval between each scan in milliseconds')
    parser.add_option('--protocol-type',
                      dest='protocol_type',
                      help='protocol type [UDP/TCP/ICMP]')
    parser.add_option('--port', '-p',
                      dest='ports',
                      help='ports [can be range : -p 22-54,'
                           'can be single port : -p 80, can be combination '
                           ': -p 80,43,23,125]')
    parser.add_option('--type',
                      dest='scan_type',
                      default='full',
                      help='scan type [full, stealth, fin, ack]')
    parser.add_option('--banner_grabber', '-b',
                      dest='banner_grabber',
                      action='store_true',
                      help='bannerGrabber status (Should work only for TCP)')
    parser.add_option('--scan',
                      dest='scan',
                      action='store_true',
                      help='scan the ip range for ICMP replies')
    parser.add_option('--ip-range',
                      dest='ip_range',
                      help='ip range. Should be used only with "--scan" option. '
                           'Example: 10.0.0.0-10.0.0.255')

    return parser.parse_args()


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

    def port_scanner_full(self):
        """
        Scans the ports of the given ip address

        """
        _socket_type = None
        _socket_family = socket.AF_INET
        _ports = [self.ports]

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
            _(output_messages.DELIMITER)
        )
        print(
            _(output_messages.SCANNING.format(
                self.dst_ip_address
            ))
        )
        print(
            _(output_messages.DELIMITER)
        )

        # Start scan time
        _start_time = time.ctime()
        _t1 = datetime.now()

        try:
            for port in _ports:
                _protocol = output_messages.CANT_RECOGNIZE
                if port in basedefs.ports_mapping:
                    _protocol = basedefs.ports_mapping[port].split(',')[0]

                sock = socket.socket(_socket_family, _socket_type)
                sock.settimeout(basedefs.SOCKET_TIMEOUT)
                if self.protocol_type == 'UDP':
                    try:
                        sock.sendto(output_messages.TEST_STR, (self.dst_ip_address, int(port)))
                        recv, svr = sock.recvfrom(255)
                        print(
                            _(output_messages.OPEN_PORT.format(
                                port,
                                _protocol
                            ))
                        )

                    except socket.error:
                        pass
                    except socket.timeout:
                        pass

                _result = -1
                if self.protocol_type == 'TCP':
                    try:
                        _result = sock.connect_ex((self.dst_ip_address, int(port)))
                    except socket.error:
                        pass

                if _result == 0:
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

        # End scan time
        _t2 = datetime.now()
        _end_time = time.ctime()
        _total = _t2 - _t1

        print('\n\n')
        print(
            _(output_messages.SUMMARY)
        )
        print(
            _(output_messages.SCANNING_STARTED.format(
                _start_time
            ))
        )
        print(
            _(output_messages.SCANNING_ENDED.format(
                _end_time
            ))
        )

        print(
            _(output_messages.SCANNING_COMPLETED.format(
                _total
            ))
        )


def map_network(ip_range):
    """
    Sends ICMP packet to the ip range and maps the network

    Parameters:
        ip_range - range of ip's to scan
    """

    _is_range_valid = re.match(basedefs.IP_RANGE_REGEX, ip_range)
    if not _is_range_valid:
        print(
            _(output_messages.IP_RANGE_NOT_VALID.format(
                ip_range
            ))
        )
        sys.exit(Status.IP_ERROR)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                      socket.getprotobyname('icmp'))

    s.settimeout(basedefs.SOCKET_TIMEOUT)

    _start, _end = ip_range.replace(' ', '').split('-')[:]

    r = iptools.IpRange(_start, _end)

    for ip in r:
        try:
            s.connect((ip, 22))
            s.send(output_messages.TEST_STR)
            buf = s.recv(basedefs.BUFSIZE)

            if output_messages.TEST_STR in buf:
                print(
                    _(output_messages.IP_IS_UP.format(
                        ip
                    ))
                )
                time.sleep(1)
        except socket.error:
            pass


def main():
    (options, args) = get_args()

    if options.scan and options.ip_range:
        map_network(options.ip_range)
        sys.exit(Status.OK)

    if not options.ip:
        print(
            _(output_messages.MISSING_OPTION.format(
                '--ip'
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

    if options.scan_type == 'full':
        port_scanner.port_scanner_full()


if __name__ == '__main__':
    main()
