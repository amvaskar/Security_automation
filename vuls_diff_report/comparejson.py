# run python file from script ./comparejson.sh
# also can be run with argument parsing  
# python comparejson.py --recentfile <path/to/folder/file.json> --previousfile <path/to/folder/file.json> -l <file_location> -rf </path/to/recentfolder> -pf </path/to/previousfolder> --createJiraTicket no --email no

from pprint import pprint
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import sys
from sys import argv
import datetime
import webbrowser as wb
import simplejson as json
import restkit 
from restkit import Resource, BasicAuth, request
import argparse
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

fromaddr = config['comparejson']['fromaddr']
toaddr = config['comparejson']['toaddr'].split(',')
smtp_server = config['comparejson']['smtp_server']



def Comparejson(recent_file, previous_file, file_location, recent_file_folder, previous_file_folder, createJiraTicket, email):
	
	product_name = recent_file.split('/')[-1].split('.')[0]
	time ='{:%Y-%m-%d-%H-%M-%S}'.format(datetime.datetime.now())
	attachment = "vuls_diff_report_{0}_{1}.txt".format(product_name,time)
	first_list = []
	second_list = []

	first_file=open(recent_file)
	second_file = open(previous_file)

	
	print ("------------------------------------------------------------------------------")

	jdata1 = json.load(first_file)
	first_parse_json = jdata1['scannedCves']
	recent_compared_json = jdata1['scannedAt']

	recent_compare_file = recent_compared_json

	for key1, value1 in first_parse_json.iteritems():
		CVE1 = str(key1)
		first_list.append(CVE1);

		name = (value1['affectedPackages'])
		for pack in name: 
			value_packages = (pack['name'])
			packages = str(value_packages)
			
	
	print ("------------------------------------------------------------------------------")

	jdata2 = json.load(second_file)
	second_parse_json = jdata2['scannedCves']

	previous_compare_json = jdata2['scannedAt']
	previous_compare_file = previous_compare_json

	

	for key2, value2 in second_parse_json.iteritems():
		CVE2 = str(key2)
		second_list.append(CVE2);
		
		name = (value2['affectedPackages'])
		for pack in name: 
			value_packages = (pack['name'])
			packages = str(value_packages)
			
	
	value = list(set(first_list) - set(second_list))
	print value

	with open(attachment, 'w') as f:
		print >> f, ("compared json files:")
		print >> f, ("Recent file: %s" %recent_compare_file)
		print >> f, ("Previous file: %s" %previous_compare_file)
		print >> f, ("---------------------------------------------------")
		print >> f, ("CVE id include only on Recent json and not in Previous")
		print >> f, ("---------------------------------------------------")
		for cve_item in value:
			first_packages_list = []
			first_source_link = []
			first_ubuntu_link = []
			first_parse_json = jdata1['scannedCves']
			package = first_parse_json.get(cve_item).get('affectedPackages')
			for pack_name in package:
				package_name = str(pack_name.get('name'))
				first_packages_list.append(package_name)
				
			severity_level = str(first_parse_json.get(cve_item).get('cveContents').get('ubuntu').get('severity'))
			References_link = (first_parse_json.get(cve_item).get('cveContents').get('ubuntu').get('references'))
			for link in References_link:
				source_link = str(link.get('link'))
				first_source_link.append(source_link)
				Source = str(link.get('source'))
				if Source == 'UBUNTU':
					first_ubuntu_link.append(source_link)
				else: 
					print ('')
			


			packages_info = jdata1['packages']
			CurrentVersion = (packages_info.get(package_name).get('version'))
			NewVersion =  (packages_info.get(package_name).get('newVersion'))
			CurrentVersion = str(CurrentVersion)
			NewVersion = str(NewVersion)
		
		
			print >> f, cve_item, "," ,first_packages_list, "," ,CurrentVersion, "," ,NewVersion, "," ,severity_level, "," ,first_source_link, "," ,first_ubuntu_link



		value = list(set(second_list) - set(first_list))
		print value
		print >> f, ("-------------------------------------------------")
		print >> f, ("CVE id include only Previous json and not in Recent")
		print >> f, ("-------------------------------------------------")
		for cve_item in value:
			second_packages_list = []
			second_source_link = []
			second_ubuntu_link = []
			second_parse_json = jdata2['scannedCves']
			package = second_parse_json.get(cve_item).get('affectedPackages')
			for pack_name in package:
				package_name = str(pack_name.get('name'))
				second_packages_list.append(package_name)
			severity_level = str(second_parse_json.get(cve_item).get('cveContents').get('ubuntu').get('severity'))
			References_link = (second_parse_json.get(cve_item).get('cveContents').get('ubuntu').get('references'))
			for link in References_link:
				source_link = str(link.get('link'))
				second_source_link.append(source_link)
				Source = str(link.get('source'))
				if Source == 'UBUNTU':
					second_ubuntu_link.append(source_link)
				else: 
					print ('')



			packages_info = jdata2['packages']
			CurrentVersion = (packages_info.get(package_name).get('version'))
			NewVersion =  (packages_info.get(package_name).get('newVersion'))
			CurrentVersion = str(CurrentVersion)
			NewVersion = str(NewVersion)
			
			print >> f, cve_item, "," ,second_packages_list, "," ,CurrentVersion, "," ,NewVersion, "," ,severity_level, "," ,second_source_link, "," ,second_ubuntu_link
	
	
	if first_list == second_list:
		print ("--------------------------------------------------------")
		print ("Both json file extracted is Same. NO changes are made!!")
		print ("--------------------------------------------------------")
	else:
		print ("--------------------------------------------------------")
		print (" Changes are made on Json files!!")
		print ("--------------------------------------------------------")

	if createJiraTicket == "yes":

		from jira_ticket import openfile

		openfile(attachment)
		
	else:
		print("No Jira Ticket create as per user preference")

		
	if email == "yes":
		sendmail(file_location, product_name, time)
	else:
		print("Email function is disabled. No email sent.")

def sendmail(file_location,product_name, time):

	print ("Sending Email...")

	msg = MIMEMultipart()
	msg['From'] = fromaddr
	msg['To'] = "," .join(toaddr)
	msg['Subject'] = "Vuls report Mail"
	body = "Vuls Security Report file "
	msg.attach(MIMEText(body, 'plain'))
	filename = "vuls_diff_report_%s_%s.txt" %(product_name,time)
	attachment = open("%s/vuls_diff_report_%s_%s.txt" %(file_location, product_name,time), "rb")
	p = MIMEBase('application', 'octet-stream')
	p.set_payload((attachment).read())
	encoders.encode_base64(p)

	p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
	msg.attach(p)
	s = smtplib.SMTP(smtp_server, 25)
	s.starttls()
	text = msg.as_string()
	s.sendmail(fromaddr, toaddr, text)
	s.quit()

	print ("Done!!")

if __name__ == '__main__':

	

	#try:
	parser = argparse.ArgumentParser(
	description='comparing json files for vulnerability report',
	formatter_class=argparse.RawDescriptionHelpFormatter)
	parser._action_groups.pop()
	required = parser.add_argument_group('Required arguments')
	optional = parser.add_argument_group('Optional arguments')

	required.add_argument('-r', '--recentfile', type=str, nargs='+',
					help='path to recent file')

	required.add_argument('-p', '--previousfile', type=str,
					help='path to previous file')

	required.add_argument('-l', '--filelocation', type=str,
					help='path to file location to be compared')

	required.add_argument('-rf', '--recentfilefolder', type=str,
					help='path to recent file folder')

	required.add_argument('-pf', '--previousfilefolder', type=str,
					help='path to previous file folder')

	optional.add_argument('--createJiraTicket', type=str,
					 help='option to create jira ticket (yes/no)', default='no')

	optional.add_argument('--email', type=str,
					 help='option to create send email (yes/no)', default='no')

	args = parser.parse_args()


	if args.recentfile and args.previousfile and args.filelocation and args.recentfilefolder and args.previousfilefolder and args.createJiraTicket and args.email:

		recent_file = args.recentfile[0]
		previous_file =  args.previousfile
		file_location = args.filelocation
		recent_file_folder = args.recentfilefolder
		previous_file_folder = args.previousfilefolder
		createJiraTicket = args.createJiraTicket
		email = args.email
		

		Comparejson(recent_file, previous_file, file_location, recent_file_folder, previous_file_folder, createJiraTicket, email)

	else:
		print "Use all arguments. use -h, -help for information."
	#except:
	# 	pass

	# 	print "Use correct arguments!! Incase Either one of : \n arguments not valid"