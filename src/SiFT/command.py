from mtp import MTPEntity, MTP
from login import LoginRequest


class Command:
    def __init__(self, cmd: str, ) -> None:
        self.cmd = cmd

    def execute(self):
        pass


class CommandHandler:
    def __init__(self, dir) -> None:
        self.rootdir = dir

    def handle(self, cmd: bytes):
        pass
