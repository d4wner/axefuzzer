# encoding: utf-8

from __future__ import absolute_import

import json
import mimetypes
from config import *#media_types, static_files, static_ext, save_content
import re
import base64
import thread
from urlparse import urlparse
import urllib2
import urllib

def save_cnf(args):
    """save wyproxy client options"""
    try:
        fd = open('.proxy.cnf', 'w')
        json.dump(args.__dict__, fd)
    finally:
        fd.close()

def read_cnf():
    """read wyproxy client options conf"""
    try:
        fd = open('.proxy.cnf', 'r')
        return json.load(fd)
    finally:
        fd.close()

class ResponseParser(object):
    """docstring for ResponseParser"""

    def __init__(self, f, domain_filter):
        super(ResponseParser, self).__init__()
        self.flow = f
        self.content_type = self.get_content_type()
        self.extension = self.get_extension()
        self.ispass = self.capture_pass()
        self.domain_filter = domain_filter

    def parser_data(self):
        """parser the capture response & request"""

        result = {}
        result['content_type'] = self.content_type
        result['url'] = self.get_url()
        result['path'] = self.get_path()
        result['extension'] = self.get_extension()
        result['host'] = self.get_host()
        result['port'] = self.get_port()
        result['scheme'] = self.get_scheme()
        result['method'] = self.get_method()
        result['status_code'] = self.get_status_code()
        result['date_start'] = self.flow.response.timestamp_start
        result['date_end'] = self.flow.response.timestamp_end
        result['content_length'] = self.get_content_length()
        result['static_resource'] = self.ispass
        result['header'] = self.get_header()
        result['request_header'] = self.get_request_header()
        #print dir(self.flow.request)
        #print dir(self.flow.request.body)
        
        #print dir(self.flow.request.data)
        #print dir(self.flow.request.data.first_line_format)
        # request resource is media file & static file, so pass
        if self.ispass:
            return
            """ result['content'] = None
            result['request_content'] = None
            return result """
        #only test domain_filter
        if not re.search(self.domain_filter, result['host']) and not self.domain_filter:
            return
        result['content'] = self.get_content() #if save_content else ''
        result['request_content'] = self.get_request_content() #if save_content else ''

        try:
            requests = base64.b64encode(self.assemble_request(self.flow.request))
            host = result['host']+':' + str(result['port']) 
            para_str = base64.b64encode((urlparse(result['url']).query + '&' + self.flow.request.data.content).rstrip('&'))

            cookie = {}
            cookie_items = self.flow.request.cookies.items()
            if cookie_items:
                for key,value in cookie_items:
                    cookie[key] = value
        except Exception, e:
            #print e
            return
        """   from vuln_detect import fuzzer
        try:
            fuzzer = fuzzer(requests, 'xss_detect', para_str, host , result['url'] , result['method'] ,'', result['content_length'], cookie)#, status_code)
            thread.start_new_thread(fuzzer.detect,())
            #log_value = fuzzer.detect()
        except Exception, e:
            pass """
            #print '[x]%s'+str(e)
        try:
            print '[+]Start to sending http-packet to fuzzer...'
            fuzzer_data = {'request':requests,'specific_para':'','detect_type':'all', 'host':host, 'content_length':result['content_length'], 'para_str':para_str , 'cookie':cookie, "req_url":result['url'], 'http_method': result['method'] }#,'status_code' : status_code }
            fuzzer_headers = {'Connection':'close',"Content-Type": "application/x-www-form-urlencoded"}
            fuzzer_req = urllib2.Request(snow_listener_url, fuzzer_headers)
            fuzzer_data = urllib.urlencode(fuzzer_data)
            opener = urllib2.build_opener()
            fuzzer_response = opener.open(fuzzer_req, fuzzer_data).read()
            print '[+]Sending http-packet ended...'
        except Exception, e:
            print e
        return result


    def assemble_request(self, request):
        if request.data.content is None:
            return
        head = self.assemble_request_head(request)
        body = b"".join(self.assemble_body(request.data.headers, [request.data.content]))
        return head + body

    def assemble_body(self, headers, body_chunks):
        if "chunked" in headers.get("transfer-encoding", "").lower():
            for chunk in body_chunks:
                if chunk:
                    yield b"%x\r\n%s\r\n" % (len(chunk), chunk)
            yield b"0\r\n\r\n"
        else:
            for chunk in body_chunks:
                yield chunk


    def assemble_request_head(self, request):
        first_line = self._assemble_request_line(request.data)
        headers = self._assemble_request_headers(request.data)
        return b"%s\r\n%s\r\n" % (first_line, headers)


    def _assemble_request_line(self, request_data):
        """
        Args:
            request_data (mitmproxy.net.http.request.RequestData)
        """
        form = request_data.first_line_format
        if form == "relative":
            return b"%s %s %s" % (
                request_data.method,
                request_data.path,
                request_data.http_version
            )
        elif form == "authority":
            return b"%s %s:%d %s" % (
                request_data.method,
                request_data.host,
                request_data.port,
                request_data.http_version
            )
        elif form == "absolute":
            return b"%s %s://%s:%d%s %s" % (
                request_data.method,
                request_data.scheme,
                request_data.host,
                request_data.port,
                request_data.path,
                request_data.http_version
            )
        else:
            raise RuntimeError("Invalid request form")

    def _assemble_request_headers(self, request_data):
        """
        Args:
            request_data (mitmproxy.net.http.request.RequestData)
        """
        headers = request_data.headers
        if "host" not in headers and request_data.scheme and request_data.host and request_data.port:
            headers = headers.copy()
            headers["host"] =  self.hostport(
                request_data.scheme,
                request_data.host,
                request_data.port
            )
        return bytes(headers)

    def hostport(self, scheme, host, port):
        """
            Returns the host component, with a port specifcation if needed.
        """
        if (port, scheme) in [(80, "http"), (443, "https"), (80, b"http"), (443, b"https")]:
            return host
        else:
            if isinstance(host, bytes):
                return b"%s:%d" % (host, port)
            else:
                return "%s:%d" % (host, port)


    def get_content_type(self):

        if not self.flow.response.headers.get('Content-Type'):
            return ''
        return self.flow.response.headers.get('Content-Type').split(';')[:1][0]

    def get_content_length(self):
        if self.flow.response.headers.get('Content-Length'):
            return int(self.flow.response.headers.get('Content-Length'))
        else:
            return 0

    def capture_pass(self):
        """if content_type is media_types or static_files, then pass captrue"""

        if self.extension in static_ext:
            return True

        # can't catch the content_type
        if not self.content_type:
            return False

        if self.content_type in static_files:
            return True

        http_mime_type = self.content_type.split('/')[:1]
        if http_mime_type:
            return True if http_mime_type[0] in media_types else False
        else:
            return False

    def get_header(self):
        return self.parser_header(self.flow.response.headers)

    def get_content(self):
        return self.flow.response.content

    def get_request_header(self):
        return self.parser_header(self.flow.request.headers)

    def get_request_content(self):
        return self.flow.request.content

    def get_url(self):
        return self.flow.request.url

    def get_path(self):
        return '/{}'.format('/'.join(self.flow.request.path_components))

    def get_extension(self):
        if not self.flow.request.path_components:
            return ''
        else:
            end_path = self.flow.request.path_components[-1:][0]
            split_ext = end_path.split('.')
            if not split_ext or len(split_ext) == 1:
                return ''
            else:
                return split_ext[-1:][0][:32]

    def get_scheme(self):
        return self.flow.request.scheme

    def get_method(self):
        return self.flow.request.method

    def get_port(self):
        return self.flow.request.port

    def get_host(self):
        return self.flow.request.host

    def get_status_code(self):
        return self.flow.response.status_code

    @staticmethod
    def parser_header(header):
        headers = {}
        for key, value in header.iteritems():
            headers[key] = value
        return headers
