#!/usr/bin/env python3

"""
Copyright <2018> <Jesus Llorente Santos, Aalto University>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

# Run as: ./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add --conn-dstaddr 1.2.3.4 --conn-dstport 22 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 14

import asyncio
import argparse
import logging
import socket
import struct
import sys


def synproxy_build_message(mode, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale):
    """
    Build and return synchronization message

    Message structure:
      - 32 bits: IPv4 address
      - 16 bits: Port number
      - 8  bits: Protocol
      - 8  bits: Flags
      - 16 bits: TCP MSS value
      - 8  bits: TCP SACK value [0,1]
      - 8  bits: TCP window scaling value [0-14]
    """
    # Build flags
    flags = 0
    if mode == 'flush':
        flags |= 0b0000001
        tcpmss = 0
        tcpsack = 0
        tcpwscale = 0
        port = 0
        proto = 0
    elif mode == 'add':
        flags |= 0b0000010
    elif mode == 'mod':
        flags |= 0b0000100
    elif mode == 'del':
        flags |= 0b0001000
        tcpmss = 0
        tcpsack = 0
        tcpwscale = 0
    # Pack message
    msg = socket.inet_pton(socket.AF_INET, ipaddr) + struct.pack('!HBBHBB', port, proto, flags, tcpmss, tcpsack, tcpwscale)
    # Return built message
    return msg


@asyncio.coroutine
def synproxy_sendrecv(ipaddr, port, mode, conn_ipaddr, conn_port, conn_proto, conn_tcpmss, conn_tcpsack, conn_tcpwscale):
    # Create TCP socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    # Connect TCP socket
    logger.info('Initiating connection to <{}:{}>'.format(ipaddr, port))
    yield from loop.sock_connect(sock, (ipaddr, port))
    logger.debug('Connected to <{}:{}>'.format(ipaddr, port))
    # Build control message
    msg = synproxy_build_message(mode, conn_ipaddr, conn_proto, conn_port, conn_tcpmss, conn_tcpsack, conn_tcpwscale)
    logger.debug('Sending control message <{}>'.format(msg))
    yield from loop.sock_sendall(sock, msg)
    logger.debug('Waiting for response...')
    data = yield from asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=5)
    sock.close()
    logger.info('Received response <{}>'.format(data))


def validate_arguments(args):
    # Validate IPv4 address
    try:
        socket.inet_pton(socket.AF_INET, args.ipaddr)
    except:
        logger.error('IPv4 address not valid <{}>'.format(args.ipaddr))
        sys.exit(1)

    # Validate port number
    if args.port <= 0 or args.port > 65535:
        logger.error('Port number not valid <{}>'.format(args.port))
        sys.exit(1)

    # Validate IPv4 address
    try:
        socket.inet_pton(socket.AF_INET, args.conn_dstaddr)
    except:
        logger.error('IPv4 address not valid <{}>'.format(args.conn_dstaddr))
        sys.exit(1)

    # Validate port number
    if args.conn_dstport < 0 or args.conn_dstport > 65535:
        logger.error('Port number not valid <{}>'.format(args.conn_dstport))
        sys.exit(1)

    # Validate TCP MSS value
    ## Set MAX MTU size at 9000
    if args.conn_tcpmss <= 0 or args.conn_tcpmss > 8960:
        logger.error('TCP MSS value not valid <{}> (1-8960)'.format(args.conn_tcpmss))
        sys.exit(1)

    # Validate TCP window scaling value
    if args.conn_tcpwscale < 0 or args.conn_tcpwscale > 14:
        logger.error('TCP window scale value not valid <{}> (0-14)'.format(args.conn_tcpwscale))
        sys.exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description='TCP SYN Proxy ControlPlane v0.1')
    # Socket address
    parser.add_argument('--ipaddr', type=str, default='127.0.0.1',
                        help='Dataplane IP address')
    parser.add_argument('--port', type=int, default=1,
                        help='Dataplane IP address')

    # Operation mode
    parser.add_argument('--mode', dest='mode', default='add', choices=['add', 'mod', 'del', 'flush'])

    # n-tuple connection options
    parser.add_argument('--conn-dstaddr', type=str, default='0.0.0.0',
                        metavar=('IPADDR'),
                        help='Destination IP address')
    parser.add_argument('--conn-dstport', type=int, default=0,
                        metavar=('PORT'),
                        help='Destination IP address')
    parser.add_argument('--conn-tcpmss', type=int, default=1460,
                        metavar=('TCPMSS'),
                        help='TCP MSS value')
    parser.add_argument('--conn-tcpsack',  type=int, default=1,
                        choices=[0, 1],
                        metavar=('TCPSACK'),
                        help='TCP SACK [True, False]')
    parser.add_argument('--conn-tcpwscale', type=int, default=14,
                        choices=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
                        metavar=('TCPWSCALE'),
                        help='TCP window scaling value [0-14]')

    args = parser.parse_args()
    validate_arguments(args)
    return args


# Get event loop
loop = asyncio.get_event_loop()
# Get logger instance
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('')

if __name__ == '__main__':
    # Parse arguments
    args = parse_arguments()
    logger.info('Creating connection to @{}:{}'.format(args.ipaddr, args.port))

    # Prepare coroutine with parameters for execution
    coro = synproxy_sendrecv(args.ipaddr, args.port, args.mode,
                             args.conn_dstaddr, args.conn_dstport, 6,
                             args.conn_tcpmss, args.conn_tcpsack, args.conn_tcpwscale)
    try:
        loop.run_until_complete(coro)
    except KeyboardInterrupt:
        pass

    logger.warning('Bye!')
    loop.close()
    sys.exit(0)
