import os
from SiFT.mtp import MTPEntity, MTP
from Crypto.Hash import SHA256
from os import listdir
from base64 import b64decode, b64encode


def base64e(s: str):
    return b64encode(s.encode('ascii')).decode('ascii')


def base64d(s: str):
    return b64decode(s.encode('ascii')).decode('ascii')


class Command:
    def __init__(self, cmd: str, host) -> None:
        self.cmd = cmd
        self.host = host

    def execute(self):
        mtp: MTPEntity = self.host.MTP
        data = self.cmd.strip().replace(' ', '\n')
        mtp.send_message(MTP.COMMAND_REQ, data.encode(MTP.encoding))
        self.host.cmd_handler.last_sent(data.encode(MTP.encoding))

    def choose_cmd_type(self):
        pass


class CommandHandler:
    def __init__(self, host) -> None:
        self.host = host

    def hash_command(self, command: bytes):
        hashfn = SHA256.new()
        hashfn.update(command)
        hashval = hashfn.hexdigest()
        return hashval

    def last_sent(self, cmd: bytes):
        self.last_cmd_hash = self.hash_command(cmd)

    def send(self, data: bytes):
        mtp: MTPEntity = self.host.MTP
        mtp.send_message(MTP.COMMAND_RES, data)
        return True

    def handle(self, cmd_b: bytes):
        cmd_str = cmd_b.decode(MTP.encoding)
        l = cmd_str.split('\n')
        command = l[0]
        # if command not in []:
        #       return
        if command == 'pwd':
            return self.handle_pwd(cmd_b, l)
        elif command == 'lst':
            return self.handle_lst(cmd_b, l)
        elif command == "chd":
            return self.handle_chd(cmd_b, l)
        elif command == "mkd":
            return self.handle_mkd(cmd_b,l)

    def handle_pwd(self, cmd_b: bytes, l):
        pass

    def handle_chd(self, cmd_b: bytes, l):
        pass

    def handle_lst(self, cmd_b: bytes, l):
        pass
    
    def handle_mkd(seld, cmd_b: bytes, l):
        pass

class ServerCommandHandler(CommandHandler):
    def __init__(self, host, dir) -> None:
        super().__init__(host)
        self.rootdir: str = dir
        self.cwd: str = dir
        # Kell mivel os.getcwd() a command.py lokációját adja meg current directorynak
        os.chdir(self.cwd)
        # Itt beállítjuk hogy a server directoryja legyen a current directory

    """defines what happens when pwd command is executed
        when pwd command is valid the correct response packet is created
        when pwd command is invalid error is returned 
    """

    def handle_pwd(self, cmd_b: bytes, l):
        cmd_s = cmd_b.decode(MTP.encoding)
        hashval = self.hash_command(cmd_b)
        params = cmd_s.split('\n')

        if len(params) == 1:
            status = 'success'
            resp = '\n'.join(['pwd', hashval, status, self.cwd])
        else:
            status = 'failure'
            resp = '\n'.join(['pwd', hashval, status, 'Too many arguments'])
        return self.send(resp.encode(MTP.encoding))

    def handle_lst(self, cmd_b: bytes, l):
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')
        hashval = self.hash_command(cmd_b)

        if len(params) == 1:
            status = 'success'
            ls = '\t'.join(listdir(self.cwd))
            enc_ls = base64e(ls)
            resp = '\n'.join(['lst', hashval, status, enc_ls])
        else:
            status = 'failure'
            resp = '\n'.join(['pwd', hashval, status, 'Too many arguments'])
        return self.send(resp.encode(MTP.encoding))

    """defines what happens when chd command is executed
        when the command is valid, the correct response packet is created
        when the command is invalid the correct error packet is created"""
    def handle_chd(self, cmd_b: bytes, l):

        hashval = self.hash_command(cmd_b)
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')
        try:
            os.chdir(params[1])
        except:
            status = "failure"
            resp = '\n'.join(['chd', hashval, status, 'Not a valid directory'])
        else:
            if os.getcwd() == "../data/server..":
                self.cwd = os.getcwd()
                status = 'success'
                resp = '\n'.join(['chd', hashval, status])
            # else:
            #status = 'failure'
            #resp= '\n'.join(['chd',hashval, status, 'Cannot access this directory'])

        return self.send(resp.encode(MTP.encoding))

    def handle_mkd(self, cmd_b: bytes, l):
        hashval = self.hash_command(cmd_b)
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')

        if len(params) == 1:
            status = 'failure'
            resp = '\n'.join(['mkd', hashval, status, 'Not enough arguments'])
        elif len(params > 2):
            status = 'failure'
            resp = '\n'.join(['mkd', hashval, status, 'Too many arguments'])
        else:
            os.mkdir(params[1])

        return self.send(resp.encode(MTP.encoding))

class ClientCommandHandler(CommandHandler):
    def __init__(self, host) -> None:
        return super().__init__(host)

    def handle_pwd(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        if l[2] != 'success':
            pass
        print(l[3])
        return True

    def handle_lst(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        if l[2] != 'success':
            pass
        ls = base64d(l[3]).split('\t')
        for p in ls:
            print(p)
        return True

    def handle_chd(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        if l[2] != 'success':
            pass
        if l[2] == 'failure':
            print(l[3])
        return True

    def handle_mkd(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        if l[2] != 'success':
            pass
        print(l[3])
        return True