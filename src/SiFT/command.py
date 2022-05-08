from SiFT.mtp import ITCP, MTPEntity, MTP
from SiFT.login import LoginRequest


class Command:
    def __init__(self, cmd: str, host) -> None:
        self.cmd = cmd
        self.host = host

    def execute(self):
        # feldolgozod a parancsot
        # ...
        # előállítod a subpacket-et
        # pl. chd "chd\npelda_dir" --> bytes --> data
        # data = bytes(2)
        # mtp: MTPEntity = self.host.MTP
        # mtp.send_message(MTP.COMMAND_REQ, data)
        pass

    def choose_cmd_type(self):
        pass


class CommandHandler:
    def __init__(self, dir) -> None:
        self.rootdir = dir

    def handle(self, cmd: bytes):

        pass
