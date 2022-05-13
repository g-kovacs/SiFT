#!/usr/bin/env python3
from asyncore import file_dispatcher
from distutils.command.upload import upload
import math
import os.path as path
from pathlib import Path
import asyncio
import getpass
from SiFT.login import LoginRequest
from SiFT.mtp import ITCP, ClientMTP, MTP
from SiFT.command import ClientCommandHandler, Command
from Crypto import Random
from rsa_keygen import load_publickey
from aioconsole import ainput, aprint
import sys
import getopt
from time import time_ns

loop_ = asyncio.get_event_loop()

HOST = 'localhost'
PORT = 5150
keyfile = None


class Client(asyncio.Protocol, ITCP):

    def __init__(self, loop: asyncio.AbstractEventLoop, homedir) -> None:
        self.loop = loop
        self.MTP = ClientMTP(self)
        self.key = load_publickey(keyfile)
        self.guard = loop_.create_future()
        self.homedir = homedir
        self.cmd_handler = ClientCommandHandler(self, homedir)
        self.dnl = False
        self.dnl_req = False
        self.dnl_cache = b''
        self.dnl_target = None
        self.drop = False
        self.drop_cnt = 0
        self.logged_in = False

        self.upl_ready = False
        self.upl_file = None

        self.origin_length = 0
        self.origin_content_hash = None

    def get_RSA(self):
        return self.key

    def connection_made(self, transport):
        self.transport = transport
        # first step is a login
        self.login()

    def data_received(self, data):
        # print('Data received: {!r}'.format(data.decode()))
        msg_info = self.MTP.dissect(data)
        #print("data rcvd")
        #print(msg_info)
        if msg_info is None:        # Some error
            self.loop.stop()
        self.handle_message(*msg_info)

    def handle_message(self, typ, header: bytes, payload: bytes):
        # msginfo: tuple (typ, header [bytes], payload [bytes])
        if typ == MTP.LOGIN_RES:
            if not self.logged_in:
                print("Login successful!")
                self.logged_in = True
                self.guard.set_result(True)
        elif typ == MTP.COMMAND_RES:
            self.cmd_handler.handle(payload)
            if self.upl_ready:
                self.upload(self.upl_file)
                print("HELLO")
            self.guard.set_result(True)
        elif typ in [MTP.DNLOAD_RES_0, MTP.DNLOAD_RES_1]:
            if not self.drop:
                if not self.dnl:
                    print("dnl_res without permission.")
                    self.transport.close()
                    self.loop.stop()
                else:
                    if typ == MTP.DNLOAD_RES_1:
                        data = self.dnl_cache + payload
                        with open(self.homedir / self.dnl_target, "wb") as f:
                            f.write(data)
                        self.dnl = False
                        self.dnl_req = False
                        self.dnl_cache = b''
                        self.dnl_target = None
                        self.guard.set_result(True)
                    else:
                        self.dnl_cache += payload
                        return
            else:
                self.drop_cnt += 1
                if self.drop_cnt <= 1:
                    self.dnl = False
                    self.dnl_target = False
                    self.dnl_req = False
                    self.dnl_cache = b''
                    self.guard.set_result(True)
        elif typ == MTP.UPLOAD_RES:
            self.check_rec(payload.decode(MTP.encoding))
            self.guard.set_result(True)


    def check_rec(self, payload: str):
        print(payload)
        if self.origin_content_hash != None or self.origin_length != 0:
            print("Upload verification faild")
            self.transport.close()
        else: print("Sikeres upload")

    def send_TCP(self, data):
        self.transport.write(data)

    async def handle_command(self, cmd: str):
        if self.dnl_req:
            ans = "Ready" if (cmd.lower() == "yes") else "Cancel"
            if ans == "Ready":
                self.dnl = True
                self.drop_cnt = 0
                self.drop = False
                self.guard = self.loop.create_future()
            self.MTP.send_message(MTP.DNLOAD_REQ, ans.encode(MTP.encoding))
            if ans == "Cancel":
                self.dnl_req = False
            else:   # Ready
                await self.guard
        else:
            c = cmd.split(' ')[0]
            if c not in ['pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl']:
                return
            self.guard = self.loop.create_future()
            Command(cmd, self).execute()
            await self.guard

    def connection_lost(self, exc):
        self.loop.stop()

    def login(self):
        # login_req with uname, passwd, random and a timestamp
        uname = input("Enter username: ")
        pw = getpass.getpass("enter password: ")
        rnd = Random.get_random_bytes(16).hex()
        login_req = LoginRequest(
            uname, pw, rnd, time_ns())
        print(login_req.rnd)
        self.MTP.send_login_req(login_req, self.key)

    def upload(self, file_name: str):
        with open(self.homedir / Path(file_name), 'rb') as f:
            data = f.read()
            n_chunks = math.ceil(len(data)/MTP.CHUNK_SIZE)
            for i in range(n_chunks):
                typ = MTP.UPLOAD_REQ_0 if i+1 != n_chunks else MTP.UPLOAD_REQ_1
                chunk = data[i*MTP.CHUNK_SIZE:(i+1)*MTP.CHUNK_SIZE]
                self.MTP.send_message(typ, chunk)
        self.upl_ready = False
        

async def main(client: Client):
    await client.guard
    while True:
        if client.dnl_req:
            cmd = await ainput()
            while cmd.lower() not in ["yes", "no"]:
                await aprint("Please type 'yes' or 'no'.")
                cmd = await ainput()
        else:
            cmd = await ainput('> ')
        await client.handle_command(cmd)

if __name__ == "__main__":
    dir = path.abspath("../data/client")
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hd:', ['help', 'homedir='])
    except getopt.GetoptError:
        print('Error: Unknown option detected.')
        print('Type "client.py -h" for help.')
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('Usage:')
            print('  client.py <keyfile> [-d <homedir>]')
            print('  client.py <keyfile> [--homedir <homedir>]')
            print('  <keyfile> must contain the 2048 public RSA key of the server.')
            print('  <homedir> is the home directory of the client')
            sys.exit(0)
        elif opt in ('-d', '--homedir'):
            dir = path.abspath(arg)

    if len(args) < 1:
        print('Error: Key file name is missing.')
        print('Type "client.py -h" for help.')
        sys.exit(1)
    else:
        keyfile = args[0]

    client = Client(loop_, Path(dir))
    coro = loop_.create_connection(lambda: client, HOST, PORT)
    try:
        loop_.run_until_complete(coro)
        loop_.run_until_complete(main(client))
        sys.exit(0)
    except Exception as e:
        print("\nBye.")
        sys.exit(1)
