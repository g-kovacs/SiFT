from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP


class MTP:
    encoding = 'utf_8'
    version = b'\x01\x00'
    rsv = b'\x00\x00'
    header_len = 16
    mac_len = 12

    def create_header(typ: bytes, len: int, sqn: int, rnd: bytes) -> bytes:
        header = MTP.version + typ
        header += len.to_bytes(2, 'big')
        header += sqn.to_bytes(2, 'big')
        header += rnd + MTP.rsv
        return header


class MTPEntity():

    def dissect(self, msg: bytes):
        return msg

    def send(self, transport, data):
        transport.write(data)


class ClientMTP(MTPEntity):
    def __init__(self, client) -> None:
        super().__init__()
        self.client = client

    def dissect(self, msg: bytes):
        return super().dissect(msg)

    def send_login_req(self, data, rsakey):
        r = Random.get_random_bytes(6)
        tk = Random.get_random_bytes(32)
        typ = b'\x00\x00'
        msg_len = MTP.header_len + len(data) + MTP.mac_len + 256
        sqn = 1
        header = MTP.create_header(typ, msg_len, sqn, r)

        nonce = sqn.to_bytes(2, 'big') + r
        AE = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=MTP.mac_len)
        encr_data, authtag = AE.encrypt_and_digest(data)

        RSAcipher = PKCS1_OAEP.new(rsakey)
        encr_tk = RSAcipher.encrypt(tk)
        self.send(self.client.transport, header +
                  encr_data + authtag + encr_tk)


class ServerMTP(MTPEntity):
    def __init__(self, server) -> None:
        super().__init__()
        self.server = server

    def dissect(self, msg: bytes):
        return super().dissect(msg)

    def send_login_res(self, transport, data):
        pass
