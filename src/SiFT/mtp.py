from Crypto import Random
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from SiFT.login import LoginRequest, LoginResponse


class ITCP:
    def send_TCP(self, data):
        pass

    def get_RSA(self):
        pass


class MTP:
    encoding = 'utf_8'
    version = b'\x01\x00'
    rsv = b'\x00\x00'
    header_len = 16
    mac_len = 12
    encr_keylen = 256
    LOGIN_REQ = b'\x00\x00'
    LOGIN_RES = b'\x00\x10'
    COMMAND_REQ = b'\x01\x00'
    COMMAND_RES = b'\x01\x10'
    UPLOAD_REQ_0 = b'\x02\x00'
    UPLOAD_REQ_1 = b'\x02\x01'
    UPLOAD_RES = b'\x02\x10'
    DNLOAD_REQ = b'\x03\x00'
    DNLOAD_RES_0 = b'\x03\x10'
    DNLOAD_RES_1 = b'\x03\x11'

    def create_header(typ: bytes, len: int, sqn: int, rnd: bytes) -> bytes:
        header = MTP.version + typ
        header += len.to_bytes(2, 'big')
        header += sqn.to_bytes(2, 'big')
        header += rnd + MTP.rsv
        return header

    def verify(msg: bytes) -> bool:
        """Check valid version and length."""

        if msg[0:2] != MTP.version:
            print("Bad MTP version, dropping packet.")
            return False
        if len(msg) != int.from_bytes(msg[4:6], 'big'):
            print("Bad length, dropping packet.")
            return False
        return True


class MTPEntity():
    def __init__(self, host: ITCP, key=None) -> None:
        self.sqn = 1
        self.rcvd_sqn = None
        self.host = host
        self.key = key

    def dissect(self, msg: bytes):
        """Check integrity of the message. If the message is valid, it is dissected, type and 
            important info are returned."""

        if not MTP.verify(msg):
            return (None,)*3
        header, payload = self.check_integrity(msg)
        if not payload:
            return (None,)*3

        typ = header[2:4]
        return typ, header, payload

    def check_integrity(self, msg: bytes):
        header, data = msg[0:MTP.header_len], msg[MTP.header_len:]
        data_len = int.from_bytes(header[4:6], 'big')
        sqn = int.from_bytes(msg[6:8], 'big')
        typ = msg[2:4]
        if typ == MTP.LOGIN_REQ:         # login_req
            if sqn != 1:    # login req with wrong sqn
                return None
            payload_len = data_len - MTP.mac_len - MTP.encr_keylen - MTP.header_len
            encr_tk = data[-MTP.encr_keylen:]
        else:                               # everything else
            if sqn != 1 and typ == MTP.LOGIN_RES:
                return None
            elif self.rcvd_sqn and sqn <= self.rcvd_sqn:
                return None
            payload_len = data_len - MTP.header_len - MTP.mac_len
        encr_payload = data[0:payload_len]
        authtag = data[payload_len: payload_len + MTP.mac_len]
        if typ == MTP.LOGIN_REQ:         # login_req
            RSA_cipher = PKCS1_OAEP.new(self.host.get_RSA())
            aes_key = RSA_cipher.decrypt(encr_tk)
        else:
            aes_key = self.key
        nonce = msg[6:14]               # sqn + rnd
        AE = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=MTP.mac_len)
        try:
            payload = AE.decrypt_and_verify(encr_payload, authtag)
        except Exception as e:
            print("Integrity check failed, droppping packet.")
            return None
        self.rcvd_sqn = sqn
        if typ == MTP.LOGIN_REQ:
            self.key = aes_key
        return header, payload

    def send(self, data):
        self.host.send_TCP(data)
        self.sqn += 1

    def create_pdu(self, typ, length, payload, AES_key) -> bytes:
        r = Random.get_random_bytes(6)
        header = MTP.create_header(typ, length, self.sqn, r)
        nonce = self.sqn.to_bytes(2, 'big') + r
        AE = AES.new(AES_key, AES.MODE_GCM, nonce=nonce, mac_len=MTP.mac_len)
        encr_data, authtag = AE.encrypt_and_digest(payload)
        return header + encr_data + authtag

    def send_message(self, typ, data):
        msg_len = MTP.header_len + len(data) + MTP.mac_len
        pdu = self.create_pdu(typ, msg_len, data, self.key)
        self.send(pdu)


class ClientMTP(MTPEntity):
    def __init__(self, client) -> None:
        super().__init__(client)

    def dissect(self, msg: bytes):
        typ, header, payload = super().dissect(msg)
        if typ == MTP.LOGIN_RES:
            rh = payload[0:-16]
            if rh != self.login_hash:
                return None
            srand = payload[-16:]
            self.key = HKDF(self.rnd + srand, 32, rh, SHA256, 1)
            del self.rnd
            return (typ,)

    def send_login_req(self, req: LoginRequest, rsakey):
        data = req.get_request()
        self.key = Random.get_random_bytes(32)      # tk
        typ = MTP.LOGIN_REQ
        msg_len = MTP.header_len + len(data) + MTP.mac_len + MTP.encr_keylen
        pdu = self.create_pdu(typ, msg_len, data, self.key)

        RSAcipher = PKCS1_OAEP.new(rsakey)
        encr_tk = RSAcipher.encrypt(self.key)

        # store request hash
        hashfn = SHA256.new()
        hashfn.update(data)
        self.login_hash = hashfn.digest()
        self.rnd = req.rnd

        self.send(pdu + encr_tk)

    def send_command_req(self):
        pass


class ServerMTP(MTPEntity):
    def __init__(self, server) -> None:
        super().__init__(server)

    def dissect(self, msg: bytes):
        typ, header, payload = super().dissect(msg)

        if typ == MTP.LOGIN_REQ:
            return (typ, LoginRequest.from_bytes(payload))

    def send_login_res(self, res: LoginResponse):
        hashfn = SHA256.new()
        hashfn.update(res.req.get_request())
        request_hash = hashfn.digest()
        # send login_res
        self.send_message(MTP.LOGIN_RES, request_hash + res.rnd)
        # update key
        self.key = HKDF(res.req.rnd + res.rnd, 32, request_hash, SHA256, 1)

    def send_command_res(self):
        pass
