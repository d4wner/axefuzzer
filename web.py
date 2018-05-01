#coding=utf-8
import bottle
from bottle import get, post, request, route, install, template
import sqlite3
import time
import thread
from config import *

@route('/listener', method='POST')
def listener():
	specific_para = ""
	content_length = ""
	cookie = ""
	detect_type = request.POST.get('detect_type')
	specific_para = request.POST.get('specific_para')
	requests = request.POST.get('request')
	host = request.POST.get('host')
	content_length = request.POST.get('content_length')
	para_str = request.POST.get('para_str')
	cookie = request.POST.get('cookie')
	req_url = request.POST.get('req_url')
	http_method = request.POST.get('http_method')
	#status_code = request.POST.get('status_code')
	#print host
	from vuln_detect import fuzzer
	try:
		fuzzer = fuzzer(requests, detect_type, para_str, host ,req_url , http_method ,specific_para, content_length, cookie)#, status_code)
		thread.start_new_thread(fuzzer.detect,())
		#log_value = fuzzer.detect()
	except Exception, e:
		print e


@route('/index')
def vulns():
	pentest_date = time.strftime('%Y-%m-%d',time.localtime(time.time()))
	conn = sqlite3.connect('axefuzzer.db')
	db = conn.cursor()
	db.execute('select * from vulns where pentest_date="%s"'%(pentest_date))
	rows = db.fetchall()
	db.close()
	row_name = ["主机名","请求包","漏洞类型","漏洞位置","检测日期"]
	#替换换行符，让界面更整洁
	rows_list = []
	#for row_item in row:
	#	row_item[1].replace('\r\n','<br />'))
	if rows:
		for row in rows:
			row_list = []
			for column in row:
				row_list.append(column.replace('\r\n', '<br />'))
			rows_list.append(row_list)

	if rows_list:
		output = bottle.template('make_table', rows = rows_list, title= pentest_date+"扫描检测结果",row_names = row_name )
		return output


@route('/waf')
def vulns():
	pentest_date = time.strftime('%Y-%m-%d',time.localtime(time.time()))
	conn = sqlite3.connect('axefuzzer.db')
	db = conn.cursor()
	db.execute('select * from wafs where pentest_date="%s"'%(pentest_date))
	row = db.fetchall()
	db.close()
	row_name = ["主机名","WAF类型","检测日期"]
	if row:
		output = bottle.template('make_table', rows = row, title = "WAF检测结果", row_names = row_name)
		return output

logo()
bottle.run(host='localhost', port=8083)
