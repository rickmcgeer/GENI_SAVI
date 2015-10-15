#!/usr/bin/python
import urllib, urllib2
import sys
backEndURL = 'http://127.0.0.1:22222/addUser'
#
# Shared Secret!
#
from savi-authentication import secret
# Json to read the response
import json
def createUser(userName, password, geniTenant, emailAddress):
    postData = {
        'uuid': secret,
        'userName': userName,
        'password': password,
        'tenant': geniTenant,
        'emailAddress': emailAddress
    }
    dataToSend = urllib.urlencode(postData)
    try:
        req = urllib2.Request(backEndURL, dataToSend)
        response = urllib2.urlopen(req)
        result = json.loads(response.read())
        if (result['Success']):
            return {
                "success": True
            }
        return {
            "success": False,
            "message":result['message']
        }
    except Exception as ex:
        template = "An exception of type {0} occured. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        #logging.error(message)
        return {
            "success": False,
            "message": message
        }
if (len(sys.argv) > 1 and sys.argv[1] == 'fail'):
    secret = 'failure'
print createUser('rickmcg', 'password', '748e8e2fc4c1462c86e20d3ad3328dea', 'rick@mcgeer.com')
