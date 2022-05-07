import SiFT.login


class SessionData:
    def __init__(self, peername, login_req) -> None:
        self.peername = peername
        self.login_req = login_req
