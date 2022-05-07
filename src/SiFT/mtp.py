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

    def verify(msg: bytes) -> bool:
        if msg[0:2] != MTP.version:
            return False
        if len(msg) != int.from_bytes(msg[4:6], 'big'):
            return False


class MTPEntity():
    def __init__(self) -> None:
        self.sqn = 1

    def dissect(self, msg: bytes):
        if not MTP.verify(msg):
            return None

        # decrpt emg minden szar
        # .....
        # idáig

        # if typ == login_req
        # return (typ, ts, )
        return (msg[0:MTP.header_len], msg[MTP.header_len:])

    def send(self, transport, data):
        transport.write(data)

    def create_pdu(self, typ, length, payload, AES_key) -> bytes:
        r = Random.get_random_bytes(6)
        header = MTP.create_header(typ, length, self.sqn, r)
        nonce = self.sqn.to_bytes(2, 'big') + r
        AE = AES.new(AES_key, AES.MODE_GCM, nonce=nonce, mac_len=MTP.mac_len)
        encr_data, authtag = AE.encrypt_and_digest(payload)
        return header + encr_data + authtag


class ClientMTP(MTPEntity):
    def __init__(self, client) -> None:
        super().__init__()
        self.client = client

    def dissect(self, msg: bytes):
        return super().dissect(msg)

    def send_login_req(self, data, rsakey):
        tk = Random.get_random_bytes(32)
        typ = b'\x00\x00'
        msg_len = MTP.header_len + len(data) + MTP.mac_len + 256
        pdu = self.create_pdu(typ, msg_len, data, tk)

        RSAcipher = PKCS1_OAEP.new(rsakey)
        encr_tk = RSAcipher.encrypt(tk)
        self.send(self.client.transport, pdu + encr_tk)


class ServerMTP(MTPEntity):
    def __init__(self, server) -> None:
        super().__init__()
        self.server = server

    def dissect(self, msg: bytes):
        return super().dissect(msg)

    def send_login_res(self, transport, data):
        pass
