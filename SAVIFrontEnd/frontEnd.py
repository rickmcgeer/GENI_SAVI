#!/usr/bin/python
#
# SAVI Portal to take GENI certs and create SAVI users from them
#
# Use Flask as the REST server
#
from flask import Flask, request, render_template
#
# Crypto libraries to read the certs.  OpenSSL.crypto has a richer interface
# but M2Crypto.X509 has simpler verification, whch is what we use now
#
import OpenSSL.crypto
from M2Crypto import X509

import logging
import pwgen
#
# smptlib to send mail and email.mime.text to format it
# note we need a mail server running on localhost for this to work
#
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
#
# turn this down to INFO at some point
#
logging.basicConfig(filename='server.log', level=logging.DEBUG)

#
# Load the GENI Management Authority public key
#
geniCertificate = X509.load_cert('ch.geni.net-ma.pem')
geniKey = geniCertificate.get_pubkey()


#
# Get the user from the subjAltName field of the X.509 cert.
# Return None if not there.  subjAltNameField is the value of the
# subject alternate name field, and is a string in the form
# email:rick@mcgeer.com, URI:urn:publicid:IDN+ch.geni.net+user+rickmcg, URI:urn:uuid:c70db7bf-b3a4-487a-b742-f6c0b632635c
# of these, we are only interested in the second.  But to be on the safe side we'll look
# for the field 'URI:urn:publicid:'
#
def getUserName(subjAltNameFieldValue):
    if (not subjAltNameFieldValue): return None
    fields = subjAltNameFieldValue.split(',')
    nameField = [field.strip() for field in fields if field.strip().startswith('URI:urn:publicid:')]
    if (len(nameField) != 1): return None
    # We could just split on '+' and take the last one, but just to be on
    # the safe side
    fields = nameField[0].split(':')
    # we know there are at least three colons, so this is safe
    value = fields[-1]
    if (len(value) == 0): return None
    components = value.split('+')
    name = components[-1].strip()
    if(len(name) > 0): return name
    return None

#
# Make a userName for email address emailAddress.  This follows the GENI convention: userName
# is the email user name + the first three characters of the email domain: so nriga@bbn.com
# becomes nrigabbn.
#

def makeUserName(emailAddress):
    # split into userName and domain and form <name><first three letters of domain>
    userRef = emailAddress.split('@')
    initUserName = userRef[0] + userRef[1][:3]
    logging.info(initUserName)
    return initUserName
#
# Add the '@geni' suffix to the userName
#
def addAtGeni(userName):
    return userName+'_geni'

#
# create the email message to send as text
#
def successMessage(emailAddress, username, password):
    return  """
        Hi,

An account has been created for user with email address %s on the SAVI testbed.

You can find more info on using the testbed here:  (especially items 1,2,3 and 5)
https://docs.google.com/a/savinetwork.ca/document/d/1avQ7eY5z1qYYPlThVZ0kG4O1fOX_fnDpwQuoNHJbE8c/edit#heading=h.vpv83zta5yex
Your username/password: %s / %s

Please use tenant name: geniUser
SAVI nodes are (case sensitive):
CORE, EDGE-CT-1, EDGE-TR-1, EDGE-VC-1, EDGE-CG-1, EDGE-MG-1, EDGE-YK-1

Please let us know if you have any questions.

Thanks""" % (emailAddress, username, password)

#
# send mail from the SAVI Server
#
def sendMailFromSAVI(emailAddress, username, password):
    txt = successMessage(username, emailAddress, password)
    msg_mail = MIMEMultipart()
    sender = 'noreply@savinetwork.ca'

    msg_mail['From'] = sender
    msg_mail['To'] = emailAddress
    msg_mail['Subject'] = 'Welcome to SAVI'

    msg_mail.attach(MIMEText(txt))
    mailServer = smtplib.SMTP("smtp.gmail.com", 587)
    mailServer.ehlo()
    mailServer.starttls()
    mailServer.ehlo()
    mailServer.login(sender, 'WEe2>4PT')
    mailServer.sendmail(sender, emailAddress, msg_mail.as_string())
    mailServer.close()
    return True



#
# Send mail on success.  Need to test when there is a machine with a
# mail server installed (not worth doing this on aptlab)
#

def sendSuccessMessage(emailAddress, username, password):
    sender = 'noreply@savinetwork.ca'
    receivers = [emailAddress] # should an audit account get a copy?
    msg = successMessage(emailAddress, username, password)

    message = MIMEText(msg)
    message['Subject'] = 'Welcome to SAVI'
    message['From']  = sender
    message['To'] = emailAddress
    try:
        smtpObj = smtplib.SMTP('localhost')
        smtpObj.sendmail(sender, receivers, message.as_string())
        logging.info("Successfully sent email to %s re new user %s" % (emailAddress, username))
        return True
    except smtplib.SMTPException as ex:
        logging.error("Error %s sending  email to %s re new username %s" % (str(ex), emailAddress, username))
        return False

#
# Methods to get the back end to actually add the user
#
# We'll need urlllib, urllib2
#
import urllib, urllib2
backEndURL = 'http://iam.savitestbed.ca:22222/addUser'
#backEndURL = 'http://127.0.0.1:22222/addUser'
#
# Secret authentication information kept in a separate file which is NOT
# github'd.  Should be stored in and loaded from a secure filesystem.
#
from savi-authentication import secret
# Json to read the response
import json
def createUser(userName, password,  emailAddress, validUntil):
    postData = {
        'uuid': secret,
        'userName': userName,
        'password': password,
        'emailAddress': emailAddress,
        'validUntil': validUntil
    }
    dataToSend = urllib.urlencode(postData)
    logging.info('POST Request sent to add user ' + json.dumps(postData))
    try:
        req = urllib2.Request(backEndURL, dataToSend)
        response = urllib2.urlopen(req)
        return json.loads(response.read())
    except urllib2.HTTPError as ex:
        message = "An Exception of type HTTPError occured.  Code = %d; reason = %s" % (ex.code, ex.reason)
        logging.error(message)
        return {
            "Success": False,
            "message": message

        }
    except Exception as ex:
        template = "An exception of type {0} occured. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        logging.error(message)
        return {
            "Success": False,
            "message": message
        }

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
    return render_template('index.html')

#
# Test templates and parameters
#
@app.route('/hello/<name>')
def hello(name):
    """ Displays the page and greets who ever comes to visit it.
    """
    return render_template('hello.html', name=name)
#
# A test method to check a specific cert against one stored on the
# server.  Used only for early testing.  Just makes sure that the
# load of the cert is the same as the one on disk and we can parse it.
# should be deleted
#
@app.route('/test_read', methods=['POST'])
def testRead():
    certText1 = request.form['cert']
    certText = certText1.encode('ascii')
    foo = open('foo.pem')
    bar = foo.read()
    if (bar == certText):
        logging.debug('Read OK')
    else:
        logging.debug('stored:\n%s\nread:\n%s' % (bar, certText))
    logging.debug('Creating cert from file\n')
    certBar = X509.load_cert_string(bar, X509.FORMAT_PEM)
    logging.debug('Creating cert from POST data')
    cert = X509.load_cert_string(certText, X509.FORMAT_PEM)
#
# The main routine which services the request.
# gets the cert, verifies it (TODO: catch a bad-cert error and return)
# If it verifies, dig out the email address of the user (subject in X509 cert)
# Check to see if there is already an account for that email address.  If so,
# return that.  If not, create the user, then set his email address and display
# the new username and password
# TODO: these should be sent by mail from noreply@savinetwork.ca and a generic success
# page displayed.
#
@app.route('/geni', methods=['POST'])
def geniUser():
    #
    # Get the certificate.  POST request data comes in in unicode and this makes the
    # ssl parser very unhappy, so re-encode in ascii.
    certText1 = request.form['cert']
    certText = certText1.encode('ascii')
    try:
        cert = X509.load_cert_string(certText, X509.FORMAT_PEM)
    except Exception as ex:
        return render_template('error.html', message = 'Failed to parse GENI certficate: %s' % str(ex))
    # old and dead -- X509 verifies and Openssl.crypto doesn't.
    # cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certText)
    # Verify the cert against the GENI Key
    code = cert.verify(geniKey)
    if(code != 1):
        return render_template('error.html', message='Error: signature verifcation code failure %d' % code)
    # get the subject's email address
    issuer = cert.get_issuer()
    subject = cert.get_subject()
    emailAddress = subject.Email

    # get the Subject Alternate Name field and pull the geni user name from that
    userName  = None
    for i in range(0, cert.get_ext_count()):
        ext = cert.get_ext_at(i)
        if (ext.get_name() == 'subjectAltName'):
            userName = getUserName(ext.get_value())
            break
    # If this failed, for whatever reason, make the name from the email address
    if (not userName):
        userName = makeUserName(emailAddress)
    validTil = str(cert.get_not_after())

    userName = addAtGeni(userName)
    #
    # generate a random password
    #
    password=pwgen.pwgen(8, no_symbols=True)

    resultReport = createUser(userName, password, emailAddress, validTil)
    if (not resultReport["Success"]):
        return render_template('report.html', username=userName, emailAddress=emailAddress, message=resultReport['message'], success=False)
    #
    # Send a success email
    #
    userName = resultReport['userName']
    emailSent = sendMailFromSAVI(emailAddress, userName, password)
    if (emailSent):
        emailSuccessMessage = 'email from noreply@savinetwork.ca sent to %s with login information' % emailAddress
    else:
        emailSuccessMessage = 'email send failed for %s.  Please log in immediately using user name %s and password %s and change your password.' % (emailAddress, userName, password)
    # Return a success report.
    return render_template('report.html', username=userName, emailAddress=emailAddress, success=True, emailSuccessMessage=emailSuccessMessage)

#
# Run the server on 5001.
#
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5001, debug=True)
