from urllib import response
from mitmproxy import http
from mitmproxy import ctx
import os
import re
import urllib.request
from urllib.parse import urlparse
from pathlib import Path
import hashlib

class EditableCache:

    def response(self, flow: http.HTTPFlow) -> None:
        if isinstance(flow, http.HTTPFlow):
            if flow.response.headers["Content-Type"].find("application/octet-stream") != -1:
                url = flow.request.pretty_url
                filename = urlparse(url)
                filename.path
                filename2 = Path(filename.path).name
                with open(filename2 ,"wb") as f:
                    pageText = bytes(flow.response.content)
                    f.write(bytes(pageText))
                self.hashcal(filename2)
            if flow.response.headers["Content-Type"].find("application/msword") != -1:
                url = flow.request.pretty_url
                filename = urlparse(url)
                filename.path
                filename2 = Path(filename.path).name
                with open(filename2,"wb") as f:
                    pageText = flow.response.content
                    f.write(bytes(pageText))
                self.hashcal(filename2)
            if flow.response.headers["Content-Type"].find("application/pdf") != -1:
                url = flow.request.pretty_url
                filename = urlparse(url)
                filename.path
                filename2 = Path(filename.path).name
                with open(filename2 ,"wb") as f:
                    pageText = flow.response.content
                    f.write(bytes(pageText))
                self.hashcal(filename2)
            with open("trafficsections","ab") as tf:
                for key, value in flow.request.headers.items():
                    tf.write('{}\n'.format(flow.request.pretty_url))
                    tf.write('{}: {}\n'.format(key, value).encode())
                for key, value in flow.response.headers.items():
                    tf.write('{}: {}\n'.format(key, value).encode())
    def hashcal(self,fname):
        with open(fname, "rb") as f:
            file_hash = hashlib.md5()
            while chunk := f.read():
                file_hash.update(chunk)
            hf = open("hashes.txt","a")
            hf.writelines("{} : {} \n".format(fname,file_hash.hexdigest()))

addons = [EditableCache()]
