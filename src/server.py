#!/usr/bin/env python3

import asyncio
import os.path as path
from Crypto.Protocol.KDF import scrypt
from SiFT.mtp import ServerMTP
from keygen import load_keypair

HOST = 'localhost'
PORT = 5150


class Server(asyncio.Protocol):

    def __init__(self) -> None:
        super().__init__()
        self.MTP = ServerMTP(self)
        self.homedir = path.abspath("../data")
        self.hash_salt = 'eznemegyerossalt'
        self.logins = self.gen_login_hashes()
        self.keypair = load_keypair("privkey")

    def gen_login_hashes(self):
        plain = {"alice": "aaa", "bob": "bbb", "charlie": "ccc"}
        logins = {}
        for k in plain.keys():
            h = scrypt(plain[k], self.hash_salt, 32, 8, 8, 1)
            logins[k] = h
        return logins

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        msg_info = self.MTP.dissect(data)
        if msg_info is None:
            return
        print('Data received: {!r}'.format(msg_info))

        print('Close the client socket')
        self.transport.close()


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: Server(),
        HOST, PORT)

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
