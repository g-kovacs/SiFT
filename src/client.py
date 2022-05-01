#!/usr/bin/env python3

import asyncio

HOST = 'localhost'
PORT = 5150


class SimpleEchoClient(asyncio.Protocol):

    def __init__(self, on_con_lost) -> None:
        self.on_con_lost = on_con_lost

    def connection_made(self, transport):
        msg = input()
        transport.write(msg.encode())

    def data_received(self, data):
        print('Data received: {!r}'.format(data.decode()))

    def connection_lost(self, exc):
        print('The server closed the connection')
        self.on_con_lost.set_result(True)


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
