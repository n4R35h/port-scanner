#!/usr/bin/python

"""
Output messages for the program
"""

# Text colors
RED = '\033[0;31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
NO_COLOR = '\033[0m'

CANNOT_CONNECT = RED + 'ERROR:' + NO_COLOR \
    + 'Could not connect to server "{0}" on protocol "{1}" port "{2}"'
MISSING_OPTION = RED + 'ERROR:' + NO_COLOR + ' Missing option "{}"'
KEYBOARD_INTERRUPT = 'You pressed Ctrl+C'
SCANNING = 'Please wait, scanning remote ip "{0}"'
OPEN_PORT = 'Port "{0}": \t' + GREEN + 'Open' + NO_COLOR + ' [{1}]'
RANGE_ERROR = RED + 'ERROR:' + NO_COLOR \
                    + ' in "--ip" First argument "{0}" ' \
                      'cannot be lower then second "{1}"'
SCANNING_COMPLETED = 'Scan Completed in: {0}'
CANT_RECOGNIZE = RED + 'CANT RECOGNIZE PROTOCOL' + NO_COLOR
SCANNING_STARTED = 'Scanning started at : {0}'
SCANNING_ENDED = 'Scanning ended at : {0}'
SUMMARY = YELLOW + 'SUMMARY:' + NO_COLOR
DELIMITER = '-' * 60
IP_IS_UP = '"{0}" ' + GREEN + '\tUP' + NO_COLOR
TEST_STR = '--TEST LINE--'
CANT_IMPORT = 'Sorry, cannot import {0} module. ' \
              'Please install it and run once again'
IP_NOT_VALID = '{0} is not a valid ip address'
