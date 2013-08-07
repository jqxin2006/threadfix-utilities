from xml.dom import minidom
cwes = dict()
xmldoc = minidom.parse('cwec_v2.5.xml')
itemlist = xmldoc.getElementsByTagName('Compound_Element') + xmldoc.getElementsByTagName('Weakness')  + xmldoc.getElementsByTagName('View') + xmldoc.getElementsByTagName('Category') 

print "-- insert into ChannelType table with new type"
print "INSERT INTO ChannelType(exportinfo, name, url, version) VALUES ('For Nessus scan by product security team', 'Nessus Scan', '-', '1.0');" 




for s in itemlist :
        the_id =  int(s.attributes['ID'].value)
        the_name =  s.attributes['Name'].value
        cwes[the_id] =the_name


ids = range(1, 939) + [1000,2000]
print "\n\n\n\n"
print "-- update ChannelVulnerability"

for i in ids:
    query = "INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ((SELECT name FROM GenericVulnerability WHERE id =%s), (SELECT name FROM GenericVulnerability WHERE id =%s), (SELECT id FROM ChannelType WHERE name = 'Nessus Scan'));" % (i,i)
    print query


print "\n\n\n\n"
print "-- update ChannelSeverity"
print "INSERT INTO ChannelSeverity(code, name, numericValue, channelTypeId) VALUES ('Critical','Critical','5',(SELECT id FROM ChannelType WHERE name = 'Nessus Scan'));"
print "INSERT INTO ChannelSeverity(code, name, numericValue, channelTypeId) VALUES ('High','High','4',(SELECT id FROM ChannelType WHERE name = 'Nessus Scan'));"
print "INSERT INTO ChannelSeverity(code, name, numericValue, channelTypeId) VALUES ('Medium','Medium','3',(SELECT id FROM ChannelType WHERE name = 'Nessus Scan'));"
print "INSERT INTO ChannelSeverity(code, name, numericValue, channelTypeId) VALUES ('Low','Low','2',(SELECT id FROM ChannelType WHERE name = 'Nessus Scan'));"
print "INSERT INTO ChannelSeverity(code, name, numericValue, channelTypeId) VALUES ('Info','Info','1',(SELECT id FROM ChannelType WHERE name = 'Nessus Scan'));"


print "\n\n\n\n"
print "-- update SeverityMap"
types = ["Critical", "High", "Medium", "Low", "Info"]
for type in types:
    print "INSERT INTO SeverityMap(genericSeverityId,channelSeverityId) VALUES ((SELECT id FROM GenericSeverity where name='%s'),(SELECT id FROM ChannelSeverity WHERE  code='%s' AND channelTypeId=(SELECT id FROM ChannelType WHERE name = 'Nessus Scan')));" % (type, type)


# for mapping

print "\n\n\n\n"
print "-- Update VulnerabilityMap"

for i in ids: 
    query = "INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,(SELECT ChannelVulnerability.id FROM ChannelVulnerability, GenericVulnerability  WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Nessus Scan') AND GenericVulnerability.name=ChannelVulnerability.name AND GenericVulnerability.id=%s), %s);" % (i, i)
    print query

