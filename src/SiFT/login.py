import time
from Crypto.Protocol.KDF import scrypt

_encoding = "utf_8"


class Logins:
    def __init__(self, salt) -> None:
        self.salt = salt
        self.logins = self.gen_hashed_logins()

    def gen_hashed_logins(self):
        plain = {"alice": "aaa", "bob": "bbb", "charlie": "ccc"}
        logins = {}
        for k in plain.keys():
            h = scrypt(plain[k], self.salt, 32, 8, 8, 1)
            logins[k] = h
        return logins

    def check_login(self, uname, passwd):
        if uname not in self.logins.keys():
            return False
        return self.logins[uname] == scrypt(passwd, self.salt, 32, 8, 8, 1)


class LoginRequest():
    def __init__(self, uname: str, pw: str, rnd: str, ts: int) -> None:
        self.uname = uname
        self.pw = pw
        self.rnd = rnd
        self.ts = ts

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, LoginRequest):
            return False
        return self.get_request() == __o.get_request()

    def get_request(self) -> str:
        return f'{self.ts}\n{self.uname}\n{self.pw}\n{self.rnd}'

    def from_bytes(data: bytes):
        tmp = data.decode(_encoding).split('\n')
        print(tmp)
        return LoginRequest(tmp[1], tmp[2], tmp[3], int(tmp[0]))

    def valid_timestamp(self, ts: int, delta_s: int):
        delta_ns = delta_s * int(5e8)
        return ts - delta_ns <= self.ts and self.ts <= ts + delta_ns


class LoginResponse():
    def __init__(self, req: LoginRequest, rnd: str) -> None:
        self.req = req
        self.rnd = rnd
