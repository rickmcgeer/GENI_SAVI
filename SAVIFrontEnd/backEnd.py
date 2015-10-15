#!/usr/bin/python
#
# SAVI Portal to take GENI certs and create SAVI users from them
#
# Use Flask as the REST server
#
from flask import Flask, request, render_template
import datetime

#
# Interface to keystone and logger
#
from keystoneclient.v2_0 import client
import logging

#
# turn this down to INFO at some point
#
logging.basicConfig(filename='backEnd.log', level=logging.DEBUG)
#
# Keystone configuration.  We will add geni users to the tenant geniUsers,
# which is in the variable geniTenant
#
# Secret authentication information kept in a separate file which is NOT
# github'd.  Should be stored in and loaded from a secure filesystem.
#
from savi-authentication import adminName, password, secret
tenant_name = 'admin'
auth_url = 'http://iam.savitestbed.ca:35357/v2.0'
keystone = client.Client(username=adminName, password=password, tenant_name = tenant_name, auth_url = auth_url)
geniTenant = [tenant.id for tenant in keystone.tenants.list() if tenant.name=='geniUsers'][0]
#
# Utilities to check if the user already exists, if so what is name is, and to
# make a new user name
#
#
# Check to see if emailAddress is already in the database.  keystone is the keystone
# client initialized above
#
def isCurrentUser(emailAddress, keystone):
    currentUserList = [user for user in keystone.users.list() if user.email == emailAddress]
    return len(currentUserList) > 0
#
# Return the user name for existing user at emailAddress.  WARNING: this should never
# be called unless isCurrentUser(emailAddress, keystone) == True
#
def getCurrentUserName(emailAddress, keystone):
    currentUserList = [user.name for user in keystone.users.list() if user.email == emailAddress]
    return currentUserList[0]
#
# Make a user name unique  If user nrigabbn already
# exists, we will create nrigabbn<k> where k is chosen to be greater than all the
# nrigabbn<j>'s in keystone.  So if we already have nrigabbn0 and nrigabbn1, we will create
# nrigabbn2.  k is always >= 0, so if there are no nrigabbn<j>'s we will create nrigabbn0
#

def makeUserNameUnique(initUserName, keystone):
    # dig out all the current users
    currentUsers = [user.name for user in keystone.users.list()]
    # check for conflict
    if (initUserName in currentUsers):
        # these next two lines create the list [j | initUserName<j> is in the current user list
        # and j is an integer].  This list will be in numbers
        suffixes = [name[len(initUserName):] for name in currentUsers if name.startswith(initUserName)]
        numbers = [int(suffix) for suffix in suffixes if is_int(suffix)]
        # if there are none, then initUserName<0> is new and add it.  If there are,
        # existing numbers, find the max of them and add 1, but make sure that the number is
        # nonnegative.
        if len(numbers) == 0:
            suffix = 0
        else:
            suffix = max(numbers) + 1
            if (suffix < 0): suffix = 0
        # return <initUserName><suffix>
        return '%s%d' % (initUserName, suffix)
    # otherwise, initUserName is unique; add it
    return initUserName

# request comes in as:
#postData = {
#        'uuid': secret,
#        'userName': userName,
#        'password': password,
#        'emailAddress': emailAddress
#    }
#

#
#
# Initialize Flask
#
app = Flask(__name__)

#
# Get method to make sure the server is up and running
#
@app.route('/')
def test():
    return ('Hello, World')
#
# The main routine which services the request.
# Check to see if there is already an account for that email address.  If so,
# return that.  If not, create the user, then set his email address and display
# the new username and password
#
@app.route('/addUser', methods=['POST'])
def geniUser():
    sentSecret = request.form['uuid']
    userName = request.form['userName']
    password = request.form['password']
    emailAddress = request.form['emailAddress']
    validUntil = request.form['validUntil']
    if (secret != sentSecret):
        return json.dumps({
            "Success": False,
            "message": "Authentication Failure"
        })
    if (isCurrentUser(emailAddress, keystone)):
        currentUserName = getCurrentUserName(emailAddress, keystone)
        return json.dumps({
            "Success": False,
            "message": "User with email address %s exists with user name %s" % (emailAddress, currentUserName)
        })
    userName = makeUserNameUnique(userName, keystone)
    message = ""
    try:
        user = keystone.users.create(name=userName, password='password', tenant_id = geniTenant)
    except Exception as ex:
        template = "An exception of type {0} occured. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        logging.error(message)
    # An exception also gets rid of our handle to the user.  So see if we can
    # get it back
    if (user == None):
        users = [user for user in keystone.users.list() if user.name == userName]
        if (len(users) == 1):
            user = users[0]
        else:
            return json.dumps({
                "Success": False,
                "message": message
            })
    # Set the email address for the user
    keystone.users.update(user, email=emailAddress)
    recordFile = open('geni-users.csv', 'a')
    date = datetime.datetime.now()
    recordFile.write("'%s', '%s', '%s', '%s'\n" % (user.name, emailAddress, str(date), validUntil))
    recordFile.close()
    return json.dumps({
        "Success": True,
        "userName": userName
    })

#
# Run the server on 22222.
#
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=22222, debug=True)
