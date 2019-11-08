#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ClamAV emulator to scan mail via SSSP for viruses
#
#   Copyright 2018,2019 Andreas Thienemann <andreas@bawue.net> and
#   Copyright 2019 Jan-Jonas Sämann <jan-jonas.saemann@saenet.de>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import argparse
import os
import socket
import sys
import syslog
import pysssp
import traceback

class ssspPipe():
  name = 'clam-scan'
  sssp_socket = None

  def __init__(self, **kwargs):
      if 'sssp_socket' in kwargs:
          self.sssp_socket = kwargs['sssp_socket']

  def log(self, msg):
      syslog.syslog('{}: {}'.format(self.name, msg))

  def file(self, name):
    try:
      scanner = pysssp.sssp(self.sssp_socket)
      if not scanner.selftest():
        self.log('SAVDI selftest failed. Not scanning.')
        return (2,'Unknown: ERROR')
      if name == '-':
        with sys.stdin as f:
          result, msg = scanner.check(f)
      else:
        with open(name, 'r') as f:
          result, msg = scanner.check(f)
    except:
      self.log('Unknown SAVDI Error. {}'.format(traceback.format_exc()))
      return (2,'Unknown: ERROR')

    engine = scanner.query_engine()
    server = scanner.query_server()
    if result:
      self.log('{}, is clean.'.format(name))
    else:
      self.log('File {} reported infected with {} by SAVDI.'.format(name, msg.split()[-1]))
      return (1, 'Infected: {} FOUND'.format(msg.split()[-1]))
    return (0,'Data: OK')

def main():
  parser = argparse.ArgumentParser(description='ClamAV emulator scans files for viruses via Sophos SSSP.')
  parser.add_argument('-q', '--quarantine', action='store_true', default=False, help='Not implemented yet')
  parser.add_argument('-r', '--remove', action='store_true', default=False, help='Drop original file if ')
  parser.add_argument('-S', '--sssp_socket', default='/var/run/savdid/savdid.sock', help='Socket for communicating to sssp interface.')
  parser.add_argument('file', help='File to scan or - to read from stdin')
  args = parser.parse_args()

  syslog.openlog(ident='clam-scan', logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)
  syslog.syslog('ClamAV emulator starting using socket {}'.format(args.sssp_socket))
  pipe = ssspPipe(sssp_socket=args.sssp_socket)
  scan_rc, scan_result = pipe.file(args.file)
  syslog.syslog('ClamAV emulator stopping')
  syslog.closelog()
  if scan_result:
    print(scan_result)
  sys.exit(scan_rc)
