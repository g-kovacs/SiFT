#!/usr/bin/env python3
import os.path as path
import asyncio
import getpass
from SiFT.login import LoginRequest
from SiFT.mtp import ITCP, ClientMTP, MTP
from SiFT.command import ClientCommandHandler, Command
from SiFT.download import Downloader
from Crypto import Random
from rsa_keygen import load_publickey
from aioconsole import ainput
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
        self.dlr = Downloader()
        self.cmd_handler = ClientCommandHandler(self)

    def get_RSA(self):
        return self.key

    def connection_made(self, transport):
        self.transport = transport
        # first step is a login
        self.login()

    def data_received(self, data):
        # print('Data received: {!r}'.format(data.decode()))
        msg_info = self.MTP.dissect(data)
        if msg_info is None:        # Some error
            self.loop.stop()
        if not self.handle_message(msg_info):
            sys.exit(1)
        self.guard.set_result(True)

    def handle_message(self, msg_info: tuple):
        # msginfo: tuple (typ, payload [bytes])
        typ = msg_info[0]
        if typ == MTP.LOGIN_RES:
            print("Login successful!")
            return True
        if typ == MTP.COMMAND_RES:
            return self.cmd_handler.handle(msg_info[1])
        if typ in [MTP.DNLOAD_RES_0, MTP.DNLOAD_RES_1]:
            return self.dlr.data_received(typ, msg_info[1])

    def send_TCP(self, data):
        self.transport.write(data)

    async def handle_command(self, cmd):
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
        self.MTP.send_login_req(login_req, self.key)


async def main(client: Client):
    await client.guard
    while True:
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

    client = Client(loop_, dir)
    coro = loop_.create_connection(lambda: client, HOST, PORT)
    try:
        loop_.run_until_complete(coro)
        loop_.run_until_complete(main(client))
        sys.exit(0)
    except Exception as e:
        print("\nBye.")
        sys.exit(1)
