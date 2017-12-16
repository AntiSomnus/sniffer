"""Folling libs are used to parse http response"""
import urllib3
from io import BytesIO
from http.client import HTTPResponse

class BytesIOSocket():
    def __init__(self, content):
        self.handle = BytesIO(content)

    def makefile(self, mode):
        return self.handle
class HttpConverter():
    def __init__(self,data):
        self.sock = BytesIOSocket(data)
    def getcontent(self):
        response = HTTPResponse(self.sock)
        response.begin()
        return urllib3.HTTPResponse.from_httplib(response)