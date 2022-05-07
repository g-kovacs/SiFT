import asyncio
from aioconsole import ainput

loop_ = asyncio.get_event_loop()


class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    def connection_made(self, transport):
        self.transport = transport

    async def send_tcp(self, data):
        self.asd = self.loop.create_future()
        self.transport.write(data.encode())
        await self.asd

    def data_received(self, data):
        print('Data received: {!r}'.format(data.decode()))
        self.asd.set_result(True)

    def connection_lost(self, exc):
        print('The server closed the connection')
        self.loop.stop()


async def cmd(client: EchoClientProtocol):
    while True:
        data = await ainput('Data to send >')
        await client.send_tcp(data)


if __name__ == "__main__":
    client = EchoClientProtocol(loop_)
    coro = loop_.create_connection(lambda: client, '127.0.0.1', 8888)
    loop_.run_until_complete(coro)
    loop_.run_until_complete(cmd(client))
