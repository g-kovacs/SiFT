import time


class LoginBase:
    def __init__(self) -> None:
        self.str_encoding = 'UTF-8'


class LoginRequest(LoginBase):
    def __init__(self, uname, pw, rnd: bytes) -> None:
        super().__init__()
        self.uname = uname
        self.pw = pw
        self.rnd = rnd
        self.ts = time.time_ns()

    def get_request(self) -> bytes:
        return bytes(f'{self.ts}\n{self.uname}\n{self.pw}\n{self.rnd}', self.str_encoding)


class LoginResponse(LoginBase):
    def __init__(self) -> None:
        super().__init__()
