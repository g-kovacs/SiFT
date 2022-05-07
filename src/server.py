#!/usr/bin/env python3

import asyncio
import os.path as path
from SiFT.mtp import ServerMTP, MTP, ITCP
import SiFT.login as login
from keygen import load_keypair
from time import time_ns

HOST = 'localhost'
PORT = 5150


class Server(asyncio.Protocol, ITCP):
    _sessions = {}

    def __init__(self) -> None:
        super().__init__()
        self.MTP = ServerMTP(self)
        self.homedir = path.abspath("../data")
        self.logins = login.Logins('eznemegyerossalt')
        self.key = load_keypair("privkey")

    def get_key(self):
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
            self.handle_login_req(msg_info[1])

    def handle_login_req(self, req: login.LoginRequest):
        if not req.valid_timestamp(time_ns(), 2):
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
