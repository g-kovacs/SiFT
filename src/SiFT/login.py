import time

_encoding = "utf_8"


class LoginRequest():
    def __init__(self, uname: str, pw: str, rnd: bytes, ts=time.time_ns()) -> None:
        self.uname = uname
        self.pw = pw
        self.rnd = rnd
        self.ts = ts

    def get_request(self) -> bytes:
        return bytes(f'{self.ts}\n{self.uname}\n{self.pw}\n', _encoding) + self.rnd

    def from_bytes(data: bytes):
        rnd = data[-16:]
        tmp = data[0:-16].decode(_encoding).split('\n')
        print(tmp)
        return LoginRequest(tmp[1], tmp[2], rnd, int(tmp[0]))


class LoginResponse():
    def __init__(self) -> None:
        pass
