"""Following libs are used to parse http response"""
import urllib3
from io import BytesIO,StringIO
from http.client import HTTPResponse
import email
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
class HttpHeader():
    """Class that parse http request header.

    """
    def __init__(self,data):
        self.data=data

    def getheader(self):
        """Parse the http request header.

        Returns:
        tuple  (a string of the brief info(GET ……) , a dict of header)
        """
        content=''
        request_string=self.data
        info, headers = request_string.split('\r\n', 1)
        try:
            headers,content=headers.split('\r\n\r\n', 1)
        except:
            pass
        # construct a message from the request string
        message = email.message_from_file(StringIO(headers))
        # construct a dictionary containing the headers
        headers = dict(message.items())

        return (info,headers,content)