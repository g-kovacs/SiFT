

class MTP:
    encoding = 'utf_8'


class MTPEntity():
    def dissect(self, msg: bytes):
        return msg.decode(MTP.encoding)

    def send(self, transport, data):
        transport.write(data)


class ClientMTP(MTPEntity):
    def __init__(self, client) -> None:
        super().__init__()
        self.client = client

    def send_login_req(self, transport, data, rsakey):
        self.send(transport, data)


class ServerMTP(MTPEntity):
    def __init__(self, server) -> None:
        super().__init__()
        self.server = server

    def send_login_res(self, transport, data):
        pass
