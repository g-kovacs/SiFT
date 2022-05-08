from SiFT.mtp import ITCP, MTPEntity, MTP
from SiFT.login import LoginRequest


class Command:
    def __init__(self, cmd: str, host) -> None:
        self.cmd = cmd
        self.host = host

    def execute(self):
        pass


class CommandHandler:
    def __init__(self, dir) -> None:
        self.rootdir = dir

    def handle(self, cmd: bytes):
        pass
