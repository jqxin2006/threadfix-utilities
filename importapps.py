#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3 as lite
import sys
import requests
import uuid
import re
import time


api_key = "AZbcQQpVGwkM9NYEqwcp6sRBIyunQJyornI23Bg2yeg"
base_url = "https://10.23.246.62:8443/threadfix/rest/" 
url = "%s/teams/?apiKey=%s" % (base_url,api_key)
r = requests.get(url, verify=False)
#print r.text

# get the details of given application with id
def get_application(team_id, app_id):
    url = "%s/teams/%s/applications/%s?apiKey=%s" % (base_url, team_id, app_id, api_key)
    r = requests.get(url, verify=False)
    if r.json() is not None:
        json = r.json()
        return json["name"]
    else:
        return None

#get_application(2)   
#create new applicaiton with given name and url. Othere paramters are not working
def create_application(team_id, name, url):
    url = "%s/teams/%s/applications/new" % (base_url, team_id)
    data = {"apiKey": api_key, "name":name, "url": url, "applicationCriticality.id":"3"}
    try:
        r = requests.post(url, data=data, verify=False)
    	json_result = r.json()
    	result = json_result["id"]
    except:
	result = -1
    return result
    
filename = "appList.csv"
with  open(filename, "r") as f:
    lines = f.readlines()

for line in lines:
    line = line.strip()
    (team,name, url) = line.split(',')
    if team == "Product":
	    app_id = create_application(1,name, url)
	    print "%s,%s,%s,%s" % ("Product", name, url, app_id)
    elif team == "Foundations":
	    app_id = create_application(2,name,url)
	    print "%s,%s,%s,%s" % ("Foundations", name, url, app_id)
