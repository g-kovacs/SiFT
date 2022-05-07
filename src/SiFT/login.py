import time
from SiFT.mtp import MTP


class LoginRequest():
    def __init__(self, uname: str, pw: str, rnd: bytes) -> None:
        self.uname = uname
        self.pw = pw
        self.rnd = rnd
        self.ts = time.time_ns()

    def get_request(self) -> bytes:
        return bytes(f'{self.ts}\n{self.uname}\n{self.pw}\n{self.rnd}', MTP.encoding)


class LoginResponse():
    def __init__(self) -> None:
        pass
