#!/usr/bin/env python3

import asyncio
import math
import os.path as path

from pathlib import Path
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
        self.logged_in = False

        self.dnl_path = None
        self.homedir = dir

        self.upl_ready = False

        self.upl_req = False
        self.upl_cache = b''
        self.upl_target = None
        self.drop = False
        self.drop_cnt = 0

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
        self.handle_message(*msg_info)

    def handle_message(self, typ, header: bytes, payload: bytes):
        if typ == MTP.LOGIN_REQ:
            if self.logged_in:
                print("Got LOGIN_REQ, expecting COMMAND_REQ.")
                self.transport.close()
            self.handle_login_req(login.LoginRequest.from_bytes(payload))
        elif typ == MTP.COMMAND_REQ:
            self.cmd_handler.handle(payload)
        elif typ == MTP.DNLOAD_REQ:
            print("got dnl_req")
            print(payload.decode(MTP.encoding))
            if self.dnl and payload.decode(MTP.encoding) == "Ready":
                self.init_dnl(self.dnl_path)
            elif self.dnl and payload.decode(MTP.encoding) == "Cancel":
                self.dnl = False
            else:
                print("dnl_req without permission.")
                self.transport.close()
            print("duh")
        elif typ == MTP.UPLOAD_REQ_0 or typ == MTP.UPLOAD_REQ_1:
            if not self.drop: 
                if not self.upl_ready:
                    print("upl not possible")
                    self.transport.close()
                    self.loop.stop()
                else:
                    if typ == MTP.UPLOAD_REQ_1:
                        data = self.upl_cache + payload
                        with open(self.homedir / Path(self.upl_target), "wb") as f:
                            f.write(data)
                        self.upl = False
                        #self.dnl_req = False
                        self.upl_cache = b''
                        self.upl_target = None
                        #self.guard.set_result(True)
                    else:
                        self.upl_cache += payload
                        return
            else:
                self.drop_cnt += 1
                if self.drop_cnt <= 1:
                    self.dnl = False
                    self.upl_target = False
                    #self.dnl_req = False
                    self.upl_cache = b''
                    #self.guard.set_result(True)
            
            

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

    def init_dnl(self, path):
        with open(path, 'rb') as f:
            data = f.read()
            n_chunks = math.ceil(len(data)/MTP.CHUNK_SIZE)
            for i in range(n_chunks):
                typ = MTP.DNLOAD_RES_0 if i+1 != n_chunks else MTP.DNLOAD_RES_1
                chunk = data[i*MTP.CHUNK_SIZE:(i+1)*MTP.CHUNK_SIZE]
                self.MTP.send_message(typ, chunk)
        self.dnl = False


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
