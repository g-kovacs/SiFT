#!/usr/bin/env python3

import asyncio
import os.path as path
from SiFT.mtp import ServerMTP, MTP, ITCP
from Crypto import Random
import SiFT.login as login
from SiFT.command import ServerCommandHandler
from SiFT.download import DownloadHandler
from SiFT.upload import UploadHandler
from rsa_keygen import load_keypair
from time import time_ns
import sys
import getopt

HOST = 'localhost'
PORT = 5150
keyfile = None


class Server(asyncio.Protocol, ITCP):
    _sessions = {}

    def __init__(self, dir) -> None:
        super().__init__()
        self.MTP = ServerMTP(self)
        self.logins = login.Logins('eznemegyerossalt')
        self.key = load_keypair(keyfile)
        self.cmd_handler = ServerCommandHandler(self, dir)
        self.dl_handler = DownloadHandler()
        self.ul_handler = UploadHandler()
        self.logged_in = False

    def get_RSA(self):
        return self.key

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def send_TCP(self, data):
        self.transport.write(data)

    def data_received(self, data):
        msg_info = self.MTP.dissect(data)
        if msg_info is None:        # Some error
            self.transport.close()
            return
        self.handle_message(msg_info)

    def handle_message(self, msg_info: tuple):
        typ = msg_info[0]
        if typ == MTP.LOGIN_REQ:
            if self.logged_in:
                print("Got LOGIN_REQ, expecting COMMAND_REQ.")
                self.transport.close()
            self.handle_login_req(msg_info[1])
        elif typ == MTP.COMMAND_REQ:
            self.cmd_handler.handle(msg_info[1])
        elif typ == MTP.DNLOAD_REQ:
            self.dl_handler.handle_download()
        elif typ == MTP.UPLOAD_REQ_0:
            self.ul_handler.handle_upload()
        elif typ == MTP.UPLOAD_REQ_1:
            self.ul_handler.data_recieved()

    def handle_login_req(self, req: login.LoginRequest):
        if not req.valid_timestamp(time_ns(), 120):
            print("Timestamp not valid. DROP")
            self.transport.close()
        if not self.logins.check_login(req.uname, req.pw):
            print("Login credentials not valid. DROP")
            self.transport.close()
        self.logged_in = True
        self.MTP.send_login_res(login.LoginResponse(
            req, Random.get_random_bytes(16).hex()))


async def main(dir):
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: Server(dir),
        HOST, PORT)

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    dir = path.abspath("../data/server")
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hd:', ['help', 'rootdir='])
    except getopt.GetoptError:
        print('Error: Unknown option detected.')
        print('Type "server.py -h" for help.')
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('Usage:')
            print('  server.py <keyfile> [-d <rootdir>]')
            print('  server.py <keyfile> [--rootdir <rootdir>]')
            print('  <keyfile> must contain the 2048 bit RSA key of the server.')
            print('  <rootdir> is the root directory of the server')
            sys.exit(0)
        elif opt in ('-d', '--rootdir'):
            dir = path.abspath(arg)

    if len(args) < 1:
        print('Error: Key file name is missing.')
        print('Type "server.py -h" for help.')
        sys.exit(1)
    else:
        keyfile = args[0]
    asyncio.run(main(dir))
