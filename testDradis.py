#!/usr/bin/python
# -*- coding: utf-8 -*-
import sqlite3 as lite
import sys


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
for row in applications:
    print row[1]
    defects = query_database(query2 % row[0])
    for defect in defects:
	    count = count+1
	    print defect
   

print count
