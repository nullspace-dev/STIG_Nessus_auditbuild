#!/usr/bin/python
import xml.etree.ElementTree as ET 
import argparse
import os
import HTMLParser

from pprint import pprint
ns = '{http://checklists.nist.gov/xccdf/1.1}'
dc = '{http://purl.org/dc/elements/1.1/}'
h = HTMLParser.HTMLParser()

objRef = {}
# def show_root_info(self):
	# for item in self.root.items():
		# for n, field in enumerate(item):
			# if n == 0:
				# p = field.index('}')
				# print(f'{field[p+1:] :20}: ', end='')
			# else:
				# print(field)
				
def parseRule(rule):
	rules = {}
	rules.update( rule.attrib.items())
	for rItem in rule:
		tag = rItem.tag.replace(ns,'')		
		if 'reference' in tag or 'check' in tag:
			for sub in rItem:
				if 'reference' in tag:
					subtag = sub.tag.replace(dc,'')
				else:
					subtag = sub.tag.replace(ns,'')
				if sub.text is not None:
					rules[subtag] = sub.text
		else:
			itemDic = {}
			if len(rItem.attrib) > 0:
				itemDic.update(rule.attrib.items())
			if rItem.text is not None:
				itemDic['text'] = rItem.text
		rules[tag] = itemDic
	return rules
		
	
def parseStig(xmlfile):
	# create element tree object 	
	tree = ET.parse(xmlfile.name) 
	root = tree.getroot()
	groupitems = []
  
	# iterate news items 
	for item in root.findall('./{http://checklists.nist.gov/xccdf/1.1}Group'):		
		#pprint(item.attrib['id'])
		group = {'fileName' : xmlfile.name, 'id': item.attrib['id']}
		for child in item:
			if('Rule' in child.tag):
				group['Rule'] = parseRule(child)
			else:
				tag = child.tag.replace(ns,'')
				group[tag] = child.text
			#group[child.tag] = child.attrib			  
		# append news dictionary to news items list 
		objRef[item.attrib['id']] = group
		groupitems.append(group)
	# return news items list 
	return groupitems 

def buildAudit(stigData, auditFile):
	f = open(str(auditFile),"w+")
	f.write('<check_type:"Cisco"> \n')
	
		
	for item in stigData :
		print('<?xml version="1.0"?><collection>'+ h.unescape(item['Rule']['description']['text']).encode('utf8') +'</collection>')
		textXml = ET.fromstring('<?xml version="1.0"?><collection>'+ h.unescape(item['Rule']['description']['text']).replace('&','').encode('utf8') +'</collection>')
		ruleDict = {}
		for elem in textXml.iter():
			pprint({elem.tag: 'nothing' if elem.text is None else elem.text})			
			ruleDict.update({elem.tag: 'nothing' if elem.text is None else elem.text})
			
		refDic = {'Rule-ID': item['Rule']['check']['id'],"Vuln-ID":item['id'],"STIG-ID":item['Rule']['version']['text']}
		
		
		f.write('\n<item>\n')
		f.write('  type \t: CONFIG_CHECK \n')
		f.write('  description \t: "' + item['Rule']['version']['text'] +' - ' + item['title'] +'"\n')
		f.write('  info \t: "' + item['Rule']['title'] +'\n\n'+ ruleDict['VulnDiscussion'].encode('utf8') +'"\n')
		f.write('  solution \t: "' + item['Rule']['fixtext']['text'].encode('utf8') +'"\n')
		f.write('  reference \t: "'+ ','.join("{0}|{1}".format(key,val.replace("'",'')) for (key,val) in refDic.items()) +'"\n')
		f.write('  see_also \t: "https://iasecontent.disa.mil/stigs/zip/'+ item['fileName'] +'"\n')
		f.write('  context \t: \n')
		f.write('  item \t: \n')
		f.write('\n</item>\n\n')
		
	f.close()
##
##AUDIT Fields
## Title, Description, Rule: id, severity, weight, version, title, description
def main(): 
	parser = argparse.ArgumentParser(description='Process a STIG xml into a nessus audit file')
	parser.add_argument('stig', metavar='N', type=argparse.FileType('r'), help='the stig file you want converted')
	parser.add_argument('auditFile', metavar='N', type=str, help='the output auditFile')
	args = parser.parse_args()
	stig = parseStig(args.stig)
	buildAudit(stig, args.auditFile)
	#pprint(stig)

	  
	  
if __name__ == "__main__": 
  
	# calling main function 
	main()