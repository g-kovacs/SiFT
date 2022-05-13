import os
from pathlib import Path
from SiFT.mtp import MTPEntity, MTP
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode

from upload import Uploader



def base64e(s: str):
    return b64encode(s.encode('ascii')).decode('ascii')


def base64d(s: str):
    return b64decode(s.encode('ascii')).decode('ascii')


class Command:
    def __init__(self, cmd: str, host) -> None:
        self.cmd = cmd
        self.host = host
        self.upl_file= ""

    def execute(self):
        mtp: MTPEntity = self.host.MTP
        cmd = self.cmd.strip().replace(' ', '\n')

        ##bemente felbontésa
        params = cmd.split('\n')
        if(params[0] == 'upl'):
            if len(params) == 1:
                print('Not enough arguments.')
            elif len(params) > 2:
                print('Too many arguments.')
            try:
                ##fájlt kell megnyitni, ami a kliensen van, ez hasal el
                file_size = str(os.path.getsize(Path(os.path.realpath(params[1]))))
                f = open(Path(os.path.realpath(params[1])), "rb")
            except: 
                    print('File not exits')
            else:
                    file_content = f.read()

                    hashfn = SHA256.new()
                    hashfn.update(file_content)
                    content_hash = hashfn.hexdigest()
                    self.upl_file = params[1]
                    data = cmd + '\n' + file_size + '\n' + content_hash ##beállítjuk a data részt.
        else: data = cmd   
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
            return self.handle_mkd(cmd_b, l)
        elif command == "del":
            return self.handle_del(cmd_b, l)
        elif command == "upl":
            return self.handle_upl(cmd_b, l)
        elif command == "dnl":
            return self.handle_dnl(cmd_b, l)

    def handle_pwd(self, cmd_b: bytes, l):
        pass

    def handle_chd(self, cmd_b: bytes, l):
        pass

    def handle_lst(self, cmd_b: bytes, l):
        pass

    def handle_mkd(self, cmd_b: bytes, l):
        pass

    def handle_del(self, cmd_b: bytes, l):
        pass

    def handle_upl(self, cmd_b: bytes, l):
        pass

    def handle_dnl(self, cmd_b: bytes, l):
        pass


class ServerCommandHandler(CommandHandler):
    def __init__(self, host, dir) -> None:
        super().__init__(host)
        self.rootdir = Path(dir)
        self.cwd = self.rootdir     # abs path of cwd
        # os.chdir(self.rootdir)

    """defines what happens when pwd command is executed
        when pwd command is valid the correct response packet is created
        when pwd command is invalid error is returned
    """

    def handle_pwd(self, cmd_b: bytes, l):
        cmd_s = cmd_b.decode(MTP.encoding)
        hashval = self.hash_command(cmd_b)
        params = cmd_s.split('\n')
        path = "/"
        path += self.cwd.name if self.cwd == self.rootdir else str(
            Path.relative_to(self.cwd, self.rootdir.parent))

        if len(params) == 1:
            status = 'success'
            resp = '\n'.join(
                ['pwd', hashval, status, path])
        else:
            status = 'failure'
            resp = '\n'.join(['pwd', hashval, status, 'Too many arguments'])
        return self.send(resp.encode(MTP.encoding))

    def handle_lst(self, cmd_b: bytes, l):
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')
        hashval = self.hash_command(cmd_b)
        status = 'success'
        ls = '\t'.join(os.listdir(str(self.cwd)))
        enc_ls = base64e(ls)
        resp = '\n'.join(['lst', hashval, status, enc_ls])
        return self.send(resp.encode(MTP.encoding))

    """defines what happens when chd command is executed
        when the command is valid, the correct response packet is created
        when the command is invalid the correct error packet is created"""

    def handle_chd(self, cmd_b: bytes, l):

        hashval = self.hash_command(cmd_b)
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')
        try:
            valid = [str(p) for p in Path(os.path.realpath(
                self.cwd / params[1])).parents]
            if str(self.rootdir.parent) not in valid:
                raise Exception("Cannot leave root directory.")
            os.chdir(self.cwd / params[1])
        except Exception as e:
            status = "failure"
            resp = '\n'.join(['chd', hashval, status, e.args[0]])
        else:
            self.cwd = Path(os.getcwd())
            status = 'success'
            resp = '\n'.join(['chd', hashval, status])

        return self.send(resp.encode(MTP.encoding))

    def handle_mkd(self, cmd_b: bytes, l):
        hashval = self.hash_command(cmd_b)
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')

        if len(params) == 1:
            status = 'failure'
            resp = '\n'.join(['mkd', hashval, status, 'Not enough arguments.'])
        elif len(params) > 2:
            status = 'failure'
            resp = '\n'.join(['mkd', hashval, status, 'Too many arguments.'])
        elif "/" in params[1]:
            status = 'failure'
            resp = '\n'.join(
                ['mkd', hashval, status, 'Can only create in current directory.'])
        else:
            status = 'success'
            resp = '\n'.join(
                ['mkd', hashval, status])
            os.mkdir(os.path.realpath(self.cwd / params[1]))

        return self.send(resp.encode(MTP.encoding))
        
    def handle_del(self, cmd_b: bytes, l):
        hashval = self.hash_command(cmd_b)
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')

        if len(params) == 1:
            status = 'failure'
            resp = '\n'.join(['del', hashval, status, 'Not enough arguments.'])
        elif len(params) > 2:
            status = 'failure'
            resp = '\n'.join(['del', hashval, status, 'Too many arguments.'])
            status = 'failure'
            resp = '\n'.join(['del', hashval, status, 'Not enough arguments.'])
        elif len(params) > 2:
            status = 'failure'
            resp = '\n'.join(['del', hashval, status, 'Too many arguments.'])
        elif "/" in params[1]:
            status = 'failure'
            resp = '\n'.join(
                ['del', hashval, status, 'No such file or directory in current directory.'])
        else:
            if Path(os.path.realpath(self.cwd / params[1])).is_dir():
                try:
                    os.rmdir(os.path.realpath(self.cwd / params[1]))
                except Exception as e:
                    status = "failure"
                    resp = '\n'.join(['del', hashval, status, e.args[1]])
                else:
                    status = "success"
                    resp = '\n'.join(['del', hashval, status])
            else:
                try:
                    os.remove(os.path.realpath(self.cwd / params[1]))
                except Exception as e:
                    status = "failure"
                    resp = '\n'.join(['del', hashval, status, str(e.args)])
                else:
                    status = "success"
                    resp = '\n'.join(['del', hashval, status])

        return self.send(resp.encode(MTP.encoding))

    def handle_upl(self, cmd_b: bytes, l):
        cmd_s = cmd_b.decode(MTP.encoding)
        hashval = self.hash_command(cmd_b)
        params = cmd_s.split('\n')

        if len(params) == 1:
            status = 'reject'
            resp = '\n'.join(['dnl', hashval, status, 'Not enough arguments.'])
        elif len(params) > 2:
            status = 'reject'
            resp = '\n'.join(['dnl', hashval, status, 'Too many arguments.'])

        status = "accept"
        resp = '\n'.join(['upl', hashval, status])
        return self.send(resp.encode(MTP.encoding))

    """First it checks if the command is valid, then it queries the file size and computes the hash
        based on the target file"""
    # egy reject után kilép a kliens

    def handle_dnl(self, cmd_b: bytes, l):
        hashval = self.hash_command(cmd_b)
        cmd_s = cmd_b.decode(MTP.encoding)
        params = cmd_s.split('\n')

        if len(params) == 1:
            status = 'reject'
            resp = '\n'.join(['dnl', hashval, status, 'Not enough arguments.'])
        elif len(params) > 2:
            status = 'reject'
            resp = '\n'.join(['dnl', hashval, status, 'Too many arguments.'])
        elif "/" in params[1]:
            status = 'reject'
            resp = '\n'.join(
                ['dnl', hashval, status, 'Can only download from current directory.'])
        else:
            try:
                file_size = str(os.path.getsize(
                    Path(os.path.realpath(self.cwd / params[1]))))
                print(file_size)
                f = open(Path(os.path.realpath(self.cwd / params[1])), "rb")
                status = 'accept'
            except:
                status = 'reject'
                resp = '\n'.join(['dnl', hashval, status, 'File not exits'])
            else:
                file_content = f.read()
                content_hash = self.hash_command(file_content)
                resp = '\n'.join(
                    ['dnl', hashval, status, file_size, content_hash])

        return self.send(resp.encode(MTP.encoding))


class ClientCommandHandler(CommandHandler):
    def __init__(self, host, dir) -> None:
        super().__init__(host)
        self.dir = Path(dir)
        self.host = host

    def handle_pwd(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        print(l[3])
        return True

    def handle_lst(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        if l[2] != 'success':
            print(l[3])
        ls = base64d(l[3]).split('\t')
        for p in ls:
            print(p)
        return True

    def handle_chd(self, cmd_b: bytes, l):
        return self._handle_chd_mkd_del(cmd_b, l)

    def handle_mkd(self, cmd_b: bytes, l):
        return self._handle_chd_mkd_del(cmd_b, l)

    def handle_del(self, cmd_b: bytes, l):
        return self._handle_chd_mkd_del(cmd_b, l)

    def _handle_chd_mkd_del(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        if l[2] == 'failure':
            print(l[3])
        return True

    def handle_upl(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        print(command_str)
        if l[2] == 'accept':
           
            Uploader(self.host, Command().upl_file).upload()
            
            return True
        if l[2] == 'reject':
            print(l[3])
            return False
        return True

    def handle_dnl(self, cmd_b: bytes, l):
        command_str = cmd_b.decode(MTP.encoding)
        l = command_str.split('\n')
        if l[1] != self.last_cmd_hash:
            return False
        if l[2] == 'reject':
            print(l[3])
            return False
        print(l[3])
        print(l[4])
        return True
