
import sys
import os
from sys import argv
import webbrowser as wb
import simplejson as json
import restkit 
from restkit import Resource, BasicAuth, request
from jira.client import JIRA
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

server_url = config['jira_ticket']['server_url']
username = config['jira_ticket']['username']
password = config['jira_ticket']['password']
project = config['jira_ticket']['project']
assignee = config['jira_ticket']['assignee']
issuetype = config['jira_ticket']['issuetype']
original_estimate = config['jira_ticket']['original_estimate']

def openfile(filename):   
	with open( filename , 'rb') as file:
		word = "CVE-"
		for line in file.read().split("\n")[1::1]:
			global description
			if not word in line:
				continue
			description = line
			cve_store = ' '
			for char in line:
				cve_store +=char
			cve_id = cve_store.split(',')[0]
      summary = config['jira_ticket']['summary']
			task_summary = summary + " : " + cve_id
			createTask(server_url, username, password, project, task_summary, description)
			

def createTask(server_base_url, user, password, project, task_summary, description):

    url_ip = '<jira server url>'
    auth = BasicAuth(user, password)
    resource_name = "issue"
    complete_url = "%s/rest/api/latest/%s" % (server_base_url, resource_name)
    resource = Resource(complete_url, filters=[auth])
    data = {
    "fields": {
       "project":
       {
          "key": project
       },
       "summary": task_summary,
       "description": description,
       "issuetype": {
          "name": issuetype
          },
       "timetracking":
        {
           "originalEstimate": original_estimate,
           "remainingEstimate": " "
        },
        "assignee":{"name": assignee}
        }
    }
    print data
    response = resource.post(headers = {'Content-Type' : 'application/json', 'X-Atlassian-Token': 'nocheck'}, payload=json.dumps(data))
    print(response)
    print("*****************************")
    print("Jira Ticket have been created")

	
	
    