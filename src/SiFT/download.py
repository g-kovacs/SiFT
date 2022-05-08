# client side
class Downloader:
    def download(self):
        pass

    def data_received(self, typ: bytes, data: bytes):
        pass


# server side
class DownloadHandler:
    def handle_download(self):
        pass
