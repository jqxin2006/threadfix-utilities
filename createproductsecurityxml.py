#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3 as lite
import sys
import requests
import uuid
import re
import time
from xml.sax.saxutils import escape
import argparse
import paramiko

desc = '''This script generates XML file from Dradis notes on the server 10.23.245.200. The script first downloads the latest version of production.sqlite3 from the server. Then, the script reads all "identified issues" from given node with given label.  The converted XML can be saved into a given file which can be used to upload to Threadfixt. \n 
Example Usage:
     python createproductsecurityxml.py    "Mon Aug 7 20:52:47 CDT 2013"  "Action Logs" -o productsecurityResult.xml
	       '''
parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
parser.add_argument("scan_time", help="The scan time of this format('Mon Aug 7 20:52:47 CDT 2013')")
parser.add_argument("label", help="The label of the node within dradis.")
parser.add_argument("-o", "--outputfile", help="The filename of the output")


args = parser.parse_args()

if args.scan_time is not None:
        scan_time = args.scan_time

if args.label is not None:
        the_label = args.label


outputfile = None
if args.outputfile is not None:
        outputfile = args.outputfile



host = "10.23.245.200"                    #hard-coded
port = 22
transport = paramiko.Transport((host, port))

password = "THEPASSWORD"                #hard-coded
username = "root"                #hard-coded
password = raw_input("Please enter the password for root@%s:" % host)
try:
	transport.connect(username = username, password = password)
except:
	print "Error! Cannot connect to %s using given user name and password!" % host
	sys.exit(1)


try:
	sftp = paramiko.SFTPClient.from_transport(transport)
        localpath='./production.sqlite3'
        path = '/etc/dradis-2.9/server/db/production.sqlite3'    #hard-coded
	print "Start downlading the latest database production.sqlite3! Please wait!"
        sftp.get(path, localpath)

        sftp.close()
        transport.close()
        print 'Download done.'
except Exception as e:
	print "Error! Can not download production.sqlite3 from %s" % host
	print e
	sys.exit(1)





NEW_LINE = "bbcc5220-4a23"
NEW_WHITESPACE = "761d3ebb-09f2"
NEW_TAB = "75fb4322-03b9"


data_filename = "production.sqlite3"

query1 = "select distinct  notes.text from nodes inner join notes where notes.node_id=nodes.id and nodes.label='%s' and notes.category_id=3;"


def query_database(query):
    con = lite.connect(data_filename)
    with con:
        cur = con.cursor()
        cur.execute(query)
        rows = cur.fetchall()
    return rows


count=0

#parse the defect descripton to get CWE type, severity level, path and parameter
# current paramter and path are just random uuid
def get_details(defect):
    vulnType="Public Static Field Not Marked Final"
    severity="3"
    p = re.compile(r'Severity:.*S(\d)|Rank:.*S(\d)',re.I | re.M )
    desc = "".join([x if ord(x) < 128 else '?' for x in defect[0]])
    found = p.findall(desc)
    severity = found[0][0]+found[0][1]
    
    p = re.compile(r'\[CWE-\d+:\s+([^\]]+)\]',re.I | re.M )
    found = p.findall(desc)
    #print found
    if (len(found)>0):
        vulnType = found[0]
	vulnType = vulnType.replace("Information Exposure Through XML External Entity Reference", "Improper Restriction of XML External Entity Reference ('XXE')")
	vulnType = vulnType.replace("Information Leak Through Browser Caching", "Information Exposure Through Browser Caching")
    else:
	pass
        #print defect[0]


    p = re.compile(r'\[path]:(.+)',re.I | re.M )
    found = p.search(desc)
    if found is not None:
	    path = found.group(1)
    else:
	    path=uuid.uuid4()

    p = re.compile(r'\[parameter]:(.*)',re.I | re.M )
    found = p.search(desc)
    if found is not None:
	    parameter = found.group(1)
    else:
	    parameter =uuid.uuid4()
    
    return (vulnType, severity, parameter, path)

def generate_sample_findings(outputfile):
    output_findings = ""
    header = '''<?xml version="1.1"?>
<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ATTLIST issues ProductSecurityTestVersion CDATA "">
<!ATTLIST issues testTime CDATA "">
<!ELEMENT issue (serialNumber, type, severity, path, parameter, longDescription)>
<!ELEMENT serialNumber (#PCDATA)>
<!ELEMENT type (#PCDATA)>
<!ELEMENT severity (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT parameter (#PCDATA)>
<!ELEMENT longDescription (#PCDATA)>
]>
<issues ProductSecurityTestVersion="1.0" testTime="%s">''' % scan_time
    output_findings =  header
    issue = '''
  <issue>
    <serialNumber>%s</serialNumber>
    <type>%s</type>
    <severity>%s</severity>
    <path>%s</path>
    <parameter>%s</parameter>
    <longDescription xml:space="preserve">
       <![CDATA[%s]]>
            </longDescription>
  </issue> '''
    
    count = 0
    severity_list =["Critical","High", "Medium", "Low", "Info"]
    defects = query_database(query1 % the_label)
    for defect in defects:
            count += 1
            desc = "".join([x if ord(x) < 128 else '?' for x in defect[0]])
            (vulnType,severity,parameter,path) = get_details(defect)
            severity = severity_list[int(severity)]
            description = desc
            description = description.replace("\n", NEW_LINE)
            description = description.replace(" ", NEW_WHITESPACE)
            description = description.replace("\t", NEW_TAB)
            output_findings += issue % (uuid.uuid4(), vulnType, severity, path, parameter,description)
    
    output_findings +=  "</issues>"
    if outputfile is None:
	    print output_findings
    else:
	    try:
		    with open(outputfile, "wb") as f:
	                 f.write(output_findings)
		    print "XML results have been written to %s" % outputfile
            except Exception as e:
		    print "Error! Can not write the results to %s" % outputfile
		    print e


generate_sample_findings(outputfile)

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
#add_all_defects()
#test_severity()
#create_application(1, "mytest", "http://www.rackspace.com")
#get_team(1)
