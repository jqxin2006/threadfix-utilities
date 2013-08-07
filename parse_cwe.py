from xml.dom import minidom
cwes = dict()
xmldoc = minidom.parse('cwec_v2.5.xml')
itemlist = xmldoc.getElementsByTagName('Compound_Element') + xmldoc.getElementsByTagName('Weakness')  + xmldoc.getElementsByTagName('View') + xmldoc.getElementsByTagName('Category') 
for s in itemlist :
	    the_id =  int(s.attributes['ID'].value)
	    the_name =  s.attributes['Name'].value
	    cwes[the_id] =the_name

for k in sorted(cwes.iterkeys()):
	print '''"%s": "%s",''' % (k, cwes[k])
	name = cwes[k].replace('\\', '\\\\')
	name = name.replace('\'', '\'\'')
        query = "INSERT INTO GenericVulnerability (name, id) VALUES ('%s', '%s');" % (name, k)
        #print query

print len(itemlist)
print len(cwes)

for k in range(1,939):
	if cwes.get(k) is None:
		print  "%s does not exist" % k

