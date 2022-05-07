#!/usr/bin/env python3

import asyncio
import getpass
import SiFT.login
import SiFT.mtp
from Crypto import Random
from Crypto.Hash import SHA256
from keygen import load_publickey

HOST = 'localhost'
PORT = 5150


class SimpleEchoClient(asyncio.Protocol):

    def __init__(self, on_con_lost) -> None:
        self.on_con_lost = on_con_lost
        self.MTP = SiFT.mtp.ClientMTP(self)
        self.pubkey = load_publickey("server_pubkey")

    def connection_made(self, transport):
        self.transport = transport
        self.login()

    def data_received(self, data):
        print('Data received: {!r}'.format(data.decode()))
        type_and_payload_tuple = self.MTP.dissect(data)

    def connection_lost(self, exc):
        print('The server closed the connection')
        self.on_con_lost.set_result(True)

    def login(self):
        uname = input("Enter username: ")
        pw = getpass.getpass("enter password: ")
        rnd = Random.get_random_bytes(16)
        login_req = SiFT.login.LoginRequest(uname, pw, rnd).get_request()
        self.MTP.send_login_req(self.transport, login_req, self.pubkey)
        hashfn = SHA256.new()
        hashfn.update(login_req)
        self.login_hash = hashfn.digest()


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()

    transport, protocol = await loop.create_connection(
        lambda: SimpleEchoClient(on_con_lost),
        HOST, PORT)

    # Wait until the protocol signals that the connection
    # is lost and close the transport.
    try:
        await on_con_lost
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())
