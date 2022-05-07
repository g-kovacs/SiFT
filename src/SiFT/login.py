import time


class LoginBase:
    encoding = 'utf_8'

    def __init__(self) -> None:
        pass


class LoginRequest(LoginBase):
    def __init__(self, uname: str, pw: str, rnd: bytes) -> None:
        super().__init__()
        self.uname = uname
        self.pw = pw
        self.rnd = rnd
        self.ts = time.time_ns()

    def get_request(self) -> bytes:
        return bytes(f'{self.ts}\n{self.uname}\n{self.pw}\n{self.rnd}', LoginBase.encoding)


class LoginResponse(LoginBase):
    def __init__(self) -> None:
        super().__init__()
