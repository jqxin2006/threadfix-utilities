from xml.dom import minidom
cwes = dict()
xmldoc = minidom.parse('cwec_v2.5.xml')
itemlist = xmldoc.getElementsByTagName('Compound_Element') + xmldoc.getElementsByTagName('Weakness')  + xmldoc.getElementsByTagName('View') + xmldoc.getElementsByTagName('Category') 

print "-- Delete old entry for VulnerabilityMap"
for i in range(752,-1, -1):
    print "DELETE from VulnerabilityMap where channelVulnerabilityId=(SELECT id FROM  ChannelVulnerability WHERE channelTypeId =10 LIMIT %s , 1);" % (i)

print "\n\n\n\n"
print "-- Delete old entry for ChannelVulnerability"
print "DELETE from ChannelVulnerability WHERE channelTypeId =10;"

print "\n\n\n\n"
print "-- Delete old entry for GenericVulnerability"
print "-- DELETE from GenericVulnerability;"






print "\n\n\n\n"
print "-- Manual GenericVulnerability"

for s in itemlist :
        the_id =  int(s.attributes['ID'].value)
        the_name =  s.attributes['Name'].value
        cwes[the_id] =the_name

for k in sorted(cwes.iterkeys()):
    #print "%s: %s" % (k, cwes[k])
    name = cwes[k].replace('\\', '\\\\')
    name = name.replace('\'', '\'\'')
    old_list = range(1,809) + [830] + range(908,919) + [1000,2000]
    if k not in old_list:
        query = "INSERT INTO GenericVulnerability (name, id) VALUES ('%s', '%s');" % (name, k)
        print query
    else:
        query = "UPDATE GenericVulnerability SET name='%s' where id='%s';" % (name, k)
        print query



ids = range(1, 939) + [1000,2000]
print "\n\n\n\n"
print "-- Manual ChannelVulnerability"

for i in ids:
    query = "INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ((SELECT name FROM GenericVulnerability WHERE id =%s), (SELECT name FROM GenericVulnerability WHERE id =%s), (SELECT id FROM ChannelType WHERE name = 'Manual'));" % (i,i)
    print query


# for mapping

print "\n\n\n\n"
print "-- Manual VulnerabilityMap"

for i in ids: 
    query = "INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,(SELECT ChannelVulnerability.id FROM ChannelVulnerability, GenericVulnerability  WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND GenericVulnerability.name=ChannelVulnerability.name AND GenericVulnerability.id=%s), %s);" % (i, i)
    print query

