# client side
class Uploader:
    def upload(self, file_name):
        pass


# server side
class UploadHandler:
    def handle_upload(self):
        pass

    def data_received(self, typ: bytes, data: bytes):
        pass
