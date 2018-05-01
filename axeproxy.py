#!/usr/bin/env python
# encoding: utf-8
#Code based on ring04h@wyproxy@mitmproxy

import sys
import argparse
import logging

from utils.daemon import Daemon
from mitmproxy import flow, proxy, controller, options
from mitmproxy.proxy.server import ProxyServer
from utils.parser import ResponseParser, save_cnf, read_cnf
from utils.handle import wyproxy_request_handle, wyproxy_response_handle
#from utils.mysql import MysqlInterface
#from utils.config import prf_url
from config import *

logging.basicConfig(
    level=logging.INFO, # filename='/tmp/wyproxy.log',
    format='%(asctime)s [%(levelname)s] %(message)s',
)

class WYProxy(flow.FlowMaster):

    def __init__(self, opts, server, state, unsave_data):
        super(WYProxy, self).__init__(opts, server, state)
        self.unsave_data = unsave_data

    def run(self):
        try:
            logging.info("axeproxy started successfully...")
            flow.FlowMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()
            logging.info("Ctrl C - stopping axeproxy server")

    @controller.handler
    def request(self, f):
        wyproxy_request_handle(f)

    @controller.handler
    def response(self, f):
        wyproxy_response_handle(f)
        if not self.unsave_data:
            try:
                parser = ResponseParser(f,domain_filter)
                result = parser.parser_data()
                if not result:
                    return
                #mysqldb_io = MysqlInterface()
                #attack result           
                #mysqldb_io.insert_result(result)
            except Exception as e:
                logging.error(str(e))
        
        # memory overfull bug
        # print(len(self.state.flows))
        # print(self.state.flow_count())
        # self.state.clear()

#def post_to_prf():
#考慮重構

def start_server(proxy_port, proxy_mode, unsave_data):
    port = int(proxy_port) if proxy_port else 8080
    mode = proxy_mode if proxy_mode else 'regular'

    if proxy_mode == 'http':
        mode = 'regular'

    opts = options.Options(
        listen_port=port,
        mode=mode,
        cadir="./ssl/",
        )

    config = proxy.ProxyConfig(opts)

    state = flow.State()
    server = ProxyServer(config)
    m = WYProxy(opts, server, state, unsave_data)
    m.run()

class wyDaemon(Daemon):

    def __init__(self, pidfile, proxy_port=8080, proxy_mode='regular', unsave_data=False):
        super(wyDaemon, self).__init__(pidfile)
        self.proxy_port = proxy_port
        self.proxy_mode = proxy_mode
        self.unsave_data = unsave_data

    def run(self):
        logging.info("axeproxy is starting...")
        logging.info("Listening: 0.0.0.0:{} {}".format(
            self.proxy_port, self.proxy_mode))
        start_server(self.proxy_port, self.proxy_mode, self.unsave_data)

def run(args):

    if args.restart:
        args.port = read_cnf().get('port')
        args.mode = read_cnf().get('mode')
        args.unsave = read_cnf().get('unsave')

    if not args.pidfile:
        args.pidfile = '/tmp/wyproxy.pid'
        
    wyproxy = wyDaemon(
        pidfile = args.pidfile,
        proxy_port = args.port,
        proxy_mode = args.mode,
        #unsave_data = args.unsave
		)

    if args.daemon:
        save_cnf(args)
        wyproxy.start()
    elif args.stop:
        wyproxy.stop()
    elif args.restart:
        wyproxy.restart()
    else:
        wyproxy.run()



if __name__ == '__main__':
    logo()
    parser = argparse.ArgumentParser(description="axeproxy v 1.1 ( Code based on ring04h@wyproxy@mitmproxy, proxying and recording HTTP/HTTPs and Socks5)")
    parser.add_argument("-d","--daemon",action="store_true",
        help="start axeproxy with daemond")
    parser.add_argument("-stop","--stop",action="store_true",required=False,
        help="stop axeproxy daemond")
    parser.add_argument("-restart","--restart",action="store_true",required=False,
        help="restart axeproxy daemond")
    parser.add_argument("-pid","--pidfile",metavar="",
        help="axeproxy daemond pidfile name")
    parser.add_argument("-p","--port",metavar="",default="8081",
        help="axeproxy bind port")
    parser.add_argument("-m","--mode",metavar="",choices=['http','socks5','transparent'],default="http",
        help="axeproxy mode (HTTP/HTTPS, Socks5, Transparent)")
    """ parser.add_argument("-us","--unsave",action="store_true",required=False,
        help="Do not save records to MySQL server") """
    parser.add_argument("-df","--domain_filter", required=False, default="",
        help="The domain you would like to detect,e.g. -df baidu.com")
    args = parser.parse_args()
    global domain_filter
    domain_filter = args.domain_filter
    try:
        run(args)
    except KeyboardInterrupt:
        logging.info("Ctrl C - Stopping Client")
        sys.exit(1)

