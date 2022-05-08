#!/usr/bin/env python3

import asyncio
import getpass
import SiFT.login
import SiFT.mtp
from Crypto import Random
from Crypto.Hash import SHA256
from rsa_keygen import load_publickey
from aioconsole import ainput
import sys
import getopt
from time import time_ns

loop_ = asyncio.get_event_loop()

HOST = 'localhost'
PORT = 5150
keyfile = None


class SimpleEchoClient(asyncio.Protocol, SiFT.mtp.ITCP):

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.MTP = SiFT.mtp.ClientMTP(self)
        self.key = load_publickey(keyfile)

    def get_key(self):
        return self.key

    def connection_made(self, transport):
        self.transport = transport
        self.login()

    def data_received(self, data):
        # print('Data received: {!r}'.format(data.decode()))
        msg_info = self.MTP.dissect(data)
        if msg_info is None:        # Some error
            self.loop.stop()

        self.guard.set_result(True)

    def send_TCP(self, data):
        self.transport.write(data)

    async def handle_command(self, cmd):
        self.guard = self.loop.create_future()
        print(cmd)
        await self.guard

    def connection_lost(self, exc):
        self.loop.stop()

    def login(self):
        uname = input("Enter username: ")
        pw = getpass.getpass("enter password: ")
        rnd = Random.get_random_bytes(16)
        login_req = SiFT.login.LoginRequest(
            uname, pw, rnd, time_ns()).get_request()
        self.MTP.send_login_req(login_req, self.key)
        hashfn = SHA256.new()
        hashfn.update(login_req)
        self.login_hash = hashfn.digest()


async def main(client: SimpleEchoClient):
    while True:
        cmd = await ainput('Command >')
        await client.handle_command(cmd)

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h', ['help'])
    except getopt.GetoptError:
        print('Error: Unknown option detected.')
        print('Type "client.py -h" for help.')
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('Usage:')
            print('  client.py <keyfile>')
            print('  <keyfile> must contain the 2048 public RSA key of the server.')
            sys.exit(0)

    if len(args) < 1:
        print('Error: Key file name is missing.')
        print('Type "client.py -h" for help.')
        sys.exit(1)
    else:
        keyfile = args[0]

    client = SimpleEchoClient(loop_)
    coro = loop_.create_connection(lambda: client, HOST, PORT)
    try:
        loop_.run_until_complete(coro)
        loop_.run_until_complete(main(client))
        sys.exit(0)
    except Exception as e:
        print("Bye.")
        sys.exit(1)
