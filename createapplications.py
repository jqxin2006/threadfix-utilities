#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3 as lite
import sys
import requests
import uuid
import re
import time

apps_str = '''
PS-ID: /Email & Apps/
PS-ID: /Email & Apps/Sao Paulo
PS-ID: /Email & Apps/Directory Sync
PS-ID: /Email & Apps/Sharepoint911
PS-ID: /Experience Design/
PS-ID: /Experience Design/Support Landing Page
PS-ID: /Experience Design/Open Cloud Community
PS-ID: /Experience Design/Rackspace Webpage
PS-ID: /Foundations/
PS-ID: /Foundations/Billing Service Layer
PS-ID: /Foundations/Informatica
PS-ID: /Foundations/Autobursting
PS-ID: /Infrastructure/
PS-ID: /Infrastructure/Atom Hopper
PS-ID: /Infrastructure/Cloud Anlytics
PS-ID: /Infrastructure/Cloud Block Storage
PS-ID: /Infrastructure/Cloud Files
PS-ID: /Infrastructure/Cloudkeep
PS-ID: /Infrastructure/Cloud Networks
PS-ID: /Infrastructure/Global Auth
PS-ID: /Infrastructure/HMDB
PS-ID: /Infrastructure/Jungle Disk
PS-ID: /Infrastructure/Legacy Servers
PS-ID: /Infrastructure/Load Balancers as a Service
PS-ID: /Infrastructure/Openstack Glance
PS-ID: /Infrastructure/Openstack Nova
PS-ID: /Infrastructure/Payment Services
PS-ID: /Infrastructure/RackConnect
PS-ID: /Infrastructure/Security
PS-ID: /Infrastructure/Service Mix
PS-ID: /Infrastructure/Signup
PS-ID: /Other/Backbone Networking
PS-ID: /Other/Core
PS-ID: /Other/I Want Cloud Networks
PS-ID: /Other/Isilon
PS-ID: /Other/Ticketing Service Layer
PS-ID: /Quality & Security/
PS-ID: /Services/
PS-ID: /Services/Autoscale
PS-ID: /Services/Backup
PS-ID: /Services/Big Data as a Service
PS-ID: /Services/CDN as a Service
PS-ID: /Services/Checkmate
PS-ID: /Services/Classic Cloud Control Panel
PS-ID: /Services/Cloud Control
PS-ID: /Services/Cloud Databases
PS-ID: /Services/Cloud DNS
PS-ID: /Services/Cloud Monitoring
PS-ID: /Services/Cloud Sites
PS-ID: /Services/Hadoop
PS-ID: /Services/Managed Cloud
PS-ID: /Services/Mobile
PS-ID: /Services/My Rackspace
PS-ID: /Services/Platform as a Service
PS-ID: /Services/Private Cloud
PS-ID: /Services/Queuing
PS-ID: /Services/Reach
PS-ID: /Services/Workflow
PS-ID: /Services/Glimpse'''

apps = apps_str.split("\n")
print "Team,Application"
for app in apps:
    team = "Product"
    if (app.find("Foundations") != -1):
        team="Foundations"
    name = app.split("/")[-1]
    if len(name) > 0:
        print "%s,%s" % (team,name)
    
