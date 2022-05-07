import SiFT.login


class SessionData:
    def __init__(self, peername, login_req) -> None:
        self.peername = peername
        self.login_req = login_req
        self.live = False

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, SessionData):
            return False
        return self.peername == __o.peername and self.login_req == __o.login_req
