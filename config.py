# encoding: utf-8

# page show record size
""" show_cnt = 15
 """
# msyql dababase connection info
""" mysqldb_conn = {
    'host' : 'localhost',
    'user' : 'root',
    'password' : '',
    'db' : '',
    'charset' : 'utf8'
}
 """
# with out save http response content to database
""" save_content = True """

# http map filenames to MIME types
# https://docs.python.org/2/library/mimetypes.html
http_mimes = ['text', 'image', 'application', 'video', 'message', 'audio']

# http static resource file extension
#保留swf？
static_ext = ['js', 'css', 'ico','txt','svg','flv','jpg','png','jpeg','gif','pdf','ss3','rar','zip','avi','mp4','wmi','exe','mpeg','wav','mp3','json','appcache','cache']

# media resource files type
media_types = ['image', 'video', 'audio']

# http static resource files
static_files = [
    'text/css',
    # 'application/javascript',
    # 'application/x-javascript',
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.ms-powerpoint',
    'application/x-ms-wmd',
    'application/x-shockwave-flash',
    # 'image/x-cmu-raster',
    # 'image/x-ms-bmp',
    # 'image/x-portable-graymap',
    # 'image/x-portable-bitmap',
    # 'image/jpeg',
    # 'image/gif',
    # 'image/x-xwindowdump',
    # 'image/png',
    # 'image/vnd.microsoft.icon',
    # 'image/x-portable-pixmap',
    # 'image/x-xpixmap',
    # 'image/ief',
    # 'image/x-portable-anymap',
    # 'image/x-rgb',
    # 'image/x-xbitmap',
    # 'image/tiff',
    # 'video/mpeg',
    # 'video/x-sgi-movie',
    # 'video/mp4',
    # 'video/x-msvideo',
    # 'video/quicktime'
    # 'audio/mpeg',
    # 'audio/x-wav',
    # 'audio/x-aiff',
    # 'audio/basic',
    # 'audio/x-pn-realaudio',
]
#snow_listener
snow_listener_url = "http://localhost:8083/listener"

#SSRF、SQL盲注、命令执行盲注的root domain，如vscode.baidu.com
blind_reverse_domain = "pz35ac.ceye.io"

#sqlmap api server address
sqlmap_api_address = 'http://127.0.0.1:8775'

#盲注反射检测地址api
blind_reverse_api = 'http://api.ceye.io/v1/records?token=0c28dc05dc90d6ecaab7fa1f28d09d9b&type=%s&filter=%s'

#所有都检测傻逼了，cmd执行检测费时间，建议简化。
detect_types = ['xss','dom_xss','url_redirect','file_download','file_read','pass_by','sqli','ssrf','xxe','ssi','ssti','crlf','command_exec']


def logo():
    print '''\n
   _____               ___________                                 
  /  _  \ ___  ___ ____\_   _____/_ __________________ ___________ 
 /  /_\  \\  \/  // __ \|    __)|  |  \___   /\___   // __ \_  __ \ 
/    |    \>    <\  ___/|     \ |  |  //    /  /    /\  ___/|  | \/
\____|__  /__/\_ \\___  >___  / |____//_____ \/_____ \\___  >__|   
        \/      \/    \/    \/              \/      \/    \/       

 [+]axeproxy v1.1  based on ring04h@wyproxy@mitmproxy, thx all.
 [+]AxeFuzzer v4.0 based on demon@prf)
'''