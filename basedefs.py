#!/usr/bin/python

SOCKET_TIMEOUT = 2

ports_mapping = {
    '80': 'http, tcp',
    '443': 'https, tcp',
    '22': 'ssh, tcp',
    '21': 'ftp, udp'
}
