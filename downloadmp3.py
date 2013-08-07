import requests
import time 
import re
def get_url(id):
   
   headers = {"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:12.0) Gecko/20100101 Firefox/12.0",
	"Proxy-Connection": "keep-alive",
	"X-Requested-With": "XMLHttpRequest",
	"Referer": "http://www.ting6.cn/ting/%s.aspx" % (id)}
   the_url = "http://www.ting6.cn/book/ajax.ashx?t=%s&oid=%s" % (int(time.time()),  id)
   response = requests.get(the_url, headers=headers)
   print response.text
   m = re.search("'([^']+.mp3)'", response.text, re.I)
   if m:
   	url = m.group(1)
	return "http://www.ting6.cn%s" %  url
   else:
	return None


def download_file(id):
   the_url = get_url(id)
   filename = "%s.mp3" % id
   print "Trying to downlaod %s to %s" % (the_url, filename)
   headers = {"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:12.0) Gecko/20100101 Firefox/12.0",
		           "Proxy-Connection": "keep-alive",
			           "X-Requested-With": "XMLHttpRequest",
				           "Referer": "http://www.ting6.cn/ting/%s.aspx" % (id)}
   if the_url:
	   r = requests.get(the_url, headers=headers)
	   with open(filename, "wb") as f:
		   f.write(r.content)
	   return True
	
   return False


for i in range(15175, 15215):
    download_file(i)

	   

