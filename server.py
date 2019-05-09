#!/usr/bin/python3
from socketserver import TCPServer, StreamRequestHandler
from syslog import syslog
import socket


class Handler(StreamRequestHandler):
    def handle(self):
        self.data = self.rfile.readline().strip()
        syslog("Receive data: %s" % self.data)
        self.wfile.write(b"+ 8 PROTOCAL HOSTNAME 127.0.0.1\r\n")


class Server(TCPServer):

    # The constant would be better initialized by a systemd module
    SYSTEMD_FIRST_SOCKET_FD = 3

    def __init__(self, server_address, HandlerCls):
        # Invoke base but omit bind/listen steps (performed by systemd activation!)
        TCPServer.__init__(
            self, server_address, HandlerCls, bind_and_activate=False)
        # Override socket
        self.socket = socket.fromfd(
            self.SYSTEMD_FIRST_SOCKET_FD, self.address_family, self.socket_type)


if __name__ == "__main__":
    server_address = '/run/avahi-daemon/socket'
    server = Server(server_address, Handler)
    server.serve_forever()
