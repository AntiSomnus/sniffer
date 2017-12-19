"""Following libs are used to parse http response"""
import urllib3
from io import BytesIO
from http.client import HTTPResponse

class BytesIOSocket():
    """Class that read bytes to BytesIo.

    """
    
    def __init__(self, content):
        self.handle = BytesIO(content)

    def makefile(self, mode):
        return self.handle
class HttpConverter():
    """Class that parse BytesIo to html header and data.

    """
    
    def __init__(self,data):
        self.sock = BytesIOSocket(data)
    def getcontent(self):
        """Return content after parsing html
        
        Returns:
        response content that has attributes(.header and .content)
        """
        
        response = HTTPResponse(self.sock)
        response.begin()
        return urllib3.HTTPResponse.from_httplib(response)