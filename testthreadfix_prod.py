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

sqlInjection = "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
xss = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
test = "Improper "

xss_description = '''

Description Summary
Description Summary
Description Summary
Description Summary
Description Summary
Description Summary
Description Summary
Description Summary
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Extended Description

Cross-site scripting (XSS) vulnerabilities occur when:

1. Untrusted data enters a web application, typically from a web request.

2. The web application dynamically generates a web page that contains this untrusted data.

'''
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
    r = requests.post(url, data=data, verify=False)
    print r.text
    

# get team  details
def get_team(team_id):
    url = "%s/teams/%s?apiKey=%s" % (base_url,team_id,  api_key)
    print url
    r = requests.get(url, verify=False)
    print r.text


# create a finding for given applicaiton and team 
def add_finding(team_id, app_id, data):
    url = "%s/teams/%s/applications/%s/addFinding" % (base_url, team_id, app_id)
    r = requests.post(url, data=data, verify=False)
    try:
        json = r.json()
    except:
        print r.text
        return False 
    
    return True


finding1 = {"apiKey": api_key, 
   "vulnType": sqlInjection,
   "name": "Our first finding",
   "severity": "0",
   "nativeId": "tes1t",
   "parameter": "par1ameter",
   "longDescription":"longDescription",
   "fullUrl": "http://www.espn.com/fullUrl",
   "path":"path"}

finding2 = {"apiKey": api_key, 
   "vulnType": xss,
   "name": "Our first finding",
   "severity": "1",
   "nativeId": "testi2",
   "parameter": "parameter12",
   "longDescription": xss_description,
   "fullUrl": "http://www.espn.com/fullUrl",
   "path":"path"}


data_filename = "production.sqlite3"

query1 = "select distinct  nodes.id, nodes.label from nodes inner join notes where notes.node_id=nodes.id and notes.category_id=10;"
query2 = "select notes.text from notes where notes.category_id=10 and notes.node_id=%s"


def query_database(query):
    con = lite.connect(data_filename)
    with con:
        cur = con.cursor()
        cur.execute(query)
        rows = cur.fetchall()
    return rows


count=0

applications = query_database(query1)
'''for row in applications:
    print row[1]
    defects = query_database(query2 % row[0])
    for defect in defects:
            count = count+1

print count

sys.exit()'''
#parse the defect descripton to get CWE type, severity level, path and parameter
# current paramter and path are just random uuid
def get_details(defect):
    vulnType="Public Static Field Not Marked Final"
    severity="3"
    p = re.compile(r'Severity:.*S(\d)|Rank:.*S(\d)',re.I | re.M )
    found = p.findall(defect[0])
    severity = found[0][0]+found[0][1]
    
    p = re.compile(r'\[CWE-\d+:\s+([^\]]+)\]',re.I | re.M )
    found = p.findall(defect[0])
    print found
    if (len(found)>0):
        vulnType = found[0]
	vulnType = vulnType.replace("Information Exposure Through XML External Entity Reference", "Improper Restriction of XML External Entity Reference ('XXE')")
	vulnType = vulnType.replace("Information Leak Through Browser Caching", "Information Exposure Through Browser Caching")
    else:
	pass
        #print defect[0]
    parameter=uuid.uuid4()
    path=uuid.uuid4()
    
    #print (vulnType, severity, parameter, path)
    return (vulnType, severity, parameter, path)

#create all applications 
def create_all_applications():

    count =0
    defect_count = 0
    for row in applications:
        count+=1
        print row[1]
        create_application(row[1])
        time.sleep(1)
        print get_application(count)
        print "****Application #%s was successfully created*****" % (count)


#This function get the mapping relationship between dradis project to application id within TF
def get_mapping(filename):
   with open(filename, 'r') as f:
       lines = f.readlines()

   mapping = dict()
   for line in lines:
       line = line.strip()
       (name, id) = line.split(',')
       mapping[name] = id
   return mapping


def add_all_defects():
    count =0
    defect_count = 0
    filename = "mapping_v2.csv"
    mapping = get_mapping(filename)
    print mapping
    print len(mapping)
    for row in applications:
        count+=1
        print row[1]
	type = row[1].strip()
        #print get_application(1,count)
        app_id = mapping[type]
	team_id = '1'
	if app_id in ["9","10","11"]:
	    team_id = '2'
	
        defects = query_database(query2 % row[0])
        severity_list =[59,60,61,62,63]
        for defect in defects:
            (vulnType,severity,parameter,path) = get_details(defect)
            finding1 = {"apiKey": api_key, 
                        "vulnType": vulnType,
                        "severity": severity_list[int(severity)],
                        "nativeId": "nativeId",
                        "parameter": parameter,
                        "longDescription":defect,
                        "fullUrl": "http://www.rackspace.com/fullUrl",
                        "path":path}
            #print finding1
            defect_count += 1
        
            if (defect_count<=258):
                continue
            else:
                time.sleep(0.4)
                add_finding(team_id,app_id, finding1)
		print "**** Added %s, %s defect:  %s ****" % (team_id, app_id, defect_count)
    
    
 
severity_list =[59,60,61,62,63]
def test_severity(): 
    for sev in range(0,5):
        finding1 = {"apiKey": api_key, 
   "vulnType": "Information Exposure Through Browser Caching",
   "severity": severity_list[sev],
   "nativeId": "nativeId",
   "parameter": uuid.uuid4(),
   "longDescription":"test with severity of %s" % sev,
   "fullUrl": "http://www.rackspace.com/fullUrl",
   "path":uuid.uuid4()}
        #print finding1
        time.sleep(1)
        add_finding(1, finding1)
          


def test_vul(): 
    count =0
    defect_count = 0
    all_types=set()
    for row in applications:
        count+=1
        print row[1]
        defects = query_database(query2 % row[0])
        for defect in defects:
            (vulnType,severity,parameter,path) = get_details(defect)
            finding1 = {"apiKey": api_key, 
   "vulnType": vulnType,
   "severity": 5-int(severity),
   "nativeId": "nativeId",
   "parameter": parameter,
   "longDescription":defect,
   "fullUrl": "http://www.rackspace.com/fullUrl",
   "path":path}
        #print finding1
            defect_count += 1
            print (vulnType,severity,parameter,path)
            all_types.add(vulnType)
        
            if (defect_count<=0):
                continue
            else:
                #time.sleep(5)
                #add_finding(count, finding1)
                print "Added defect %s" % defect_count
  
    print all_types 
    for type in all_types:
        finding1 = {"apiKey": api_key, 
   "vulnType": type,
   "severity": 1,
   "nativeId": "nativeId",
   "parameter": "test",
   "longDescription":"test",
   "fullUrl": "http://www.rackspace.com/fullUrl",
   "path":"test"}
        time.sleep(3)
        if (not add_finding(1, finding1)):
            print type
         
    print count

#add_finding(finding1)
#add_finding(finding2)
#create_all_applications()
add_all_defects()
#test_severity()
#create_application(1, "mytest", "http://www.rackspace.com")
#get_team(1)
