from Crypto.Hash import SHA256
import os

from click import Path

from mtp import MTP, MTPEntity

# client side
class Uploader:
    def __init__(self, host, file_name: str) -> None:
        self.origin_file_size = os.path.getsize(Path(os.path.realpath(file_name)))
        self.file_name = file_name
        self.host = host
        self.mtp: MTPEntity = self.host.MTP

        f = open(Path(os.path.realpath(file_name)), "rb")
        file_content = f.read()
        hashfn = SHA256.new()
        hashfn.update(file_content)
        
        self.origin_content_hash = hashfn.hexdigest()


    def upload(self):
        f = open(Path(os.path.realpath(self.file_name)), "rb")

        if self.origin_file_size <= 1024:
            data = f.read()
            self.mtp.send_message(MTP.UPLOAD_REQ_1, data.encode(MTP.encoding))
        else:
            current_chunk = f.read(1024)
            while current_chunk:
                self.mtp.send_message(MTP.UPLOAD_REQ_0, current_chunk.encode(MTP.encoding)) 
                current_chunk = f.read(1024)
        pass

    def upload_check(self):
        #itt kell ellenőrizni hogy a kapott méret ls hash jó-e, erre van a 
        # origin_file_size és origin_content_hash
        pass
        
# server side
class UploadHandler:
    def handle_upload(self):
        ##itt mentünk fájlba
        pass

    def data_received(self):
        ## itt állítjuk össze a resp csomagot
        ## hossz és hash számolás
        pass
