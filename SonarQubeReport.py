#!/usr/bin/env python
import json
import os
import pprint
import requests
import sys

class SonarQubeReport:

    def __init__(self, url, user, userToken, projectKey, projectName):
        self.url = url
        self.user = user
        self.userToken = userToken
        self.projectKey = projectKey
        self.projectName = projectName
        self.severities = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"] 
        self.issues = None
        self.analysis = None
        self.stats = None
        
    def callApi(self, api):
        url = "{0}/api/{1}".format(self.url, api)
        try:
            s = requests.Session()
            response = None
            s.auth = (self.userToken, "")
            response = s.get(url)
            responseCode = int(response.status_code)
            if responseCode != 200 and responseCode != 204:
                print("ERROR: Unexpected response code: {0} when calling {1}\n{2}".
                    format(responseCode, url, response.text))
                sys.exit(1)
            return response.json()
        except ValueError:
            return None

    def getAnalysis(self):
        api = "project_analyses/search?project={0}&ps=500".format(self.projectKey)
        response = self.callApi(api)
        return response

    def getIssues(self):
        api = "issues/search?projectKeys={0}&types=VULNERABILITY" \
              "&ps=500&s=SEVERITY&statuses=OPEN&facets=severities,rules,languages" \
              "&additionalFields=languages,rules,_all&facetMode=count".format(self.projectKey) 
        response = self.callApi(api)
        total = response["total"]
        self.issues = {} 
        self.stats = {}
        for severity in self.severities:
            self.stats[severity] = 0 
        self.stats["total"] = 0
        for issue in response["issues"]:
            if issue["severity"] not in self.issues.keys():
                self.issues[issue["severity"]] = []
            self.issues[issue["severity"]].append(issue)
            self.stats[issue["severity"]] += 1 
            self.stats["total"] += 1
        return self.issues

    def writeTextReport(self):
        report = """
Project:     {0}
Scan Date:   ???
Report Date: ???
Total: {1}""".format(
self.projectName,
self.stats["total"])
        for severity in self.severities:
            report = "{0}\n  -{1}: {2}".format(report, severity.title(), self.stats[severity]) 
        print(report)
        for severity in self.severities:
            if not severity in self.issues:
                continue
            for issue in self.issues[severity]:
                report = '''
----------------------------------------------------------
[{0} {1}]

Issue:  {2} 
File:   {3}
Line:   {4}
Author: {5}
Rule:   {6}
Tags:   {7}
Status: {8}'''.format(
issue["severity"],
issue["type"],
issue["message"],
issue["component"],
issue["line"],
issue["author"],
issue["rule"],
', '.join(issue["tags"]).strip(),
issue["status"].title()
)  
                print(report)
