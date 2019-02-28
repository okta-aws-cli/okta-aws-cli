#!/usr/bin/env python

import requests
import json
import getpass
import os
import configparser
import sys
import re
import codecs
import base64
import boto3
import time
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

if not len(sys.argv) > 1:
    print("You forgot to specify a profile. Try again.")
    sys.exit(1)

display_head = os.getenv('DISPLAY')
headless_mode = True
if (display_head is not None and display_head or os.name == 'nt'):
    import keyring
    headless_mode = False

def get_password(username):
    """Handles getting the user password from keychain/keystorage/credvault"""

    try:
        password = keyring.get_password("okta-aws-cli-pwd", username)
        if password is None:
            print("Password not saved in keychain, please input your Okta account password...")
            password = getpass.getpass()
            keyring.set_password("okta-aws-cli-pwd", username, password)
            return password
        else:
            return password
    except:
        print("Running in headless mode, password input required.")
        password = getpass.getpass()
        return password

def update_password(username):
    """Update the keychain password if login returns an error"""

    print("Please enter your Okta account password: ")
    password = getpass.getpass()
    keyring.set_password("okta-aws-cli-pwd", username, password)

def option_picker(list, prompter):
    """Basic option picker"""

    print(prompter)
    for idx, element in enumerate(list):
        print("{}) {}".format(idx + 1, element))
    i = input("Enter number: ")
    try:
        if 0 < int(i) <= len(list):
            sel_idx = int(i) - 1
            return list[sel_idx]
    except:
        print("Invalid selection")
        pass
    print("Invalid selection")
    sys.exit(1)

def do_mfa(response, payload, stateToken=None):
    """Handle MFA for user"""
    mfalist = []
    for factor in response['_embedded']['factors']:
        mfalist.append(factor['provider'] + '-' + factor['factorType'])

    try:
        mymfa = config.get("default", "mfa_factor")
        print("Using " + config.get("default", "mfa_factor") + " as MFA provider")
    except:
        mymfa = option_picker(mfalist, "Default MFA not found in config, invoking configuration...")
        config.set('default', 'mfa_factor', mymfa)

    mfa = mymfa.split("-")
    factors = response['_embedded']['factors']
    factorIndex = factors.index(
        next(item for item in factors if (item['provider'] == mfa[0] and item['factorType'] == mfa[1])))
    factorType = response['_embedded']['factors'][factorIndex]['factorType']
    factorId = response['_embedded']['factors'][factorIndex]['id']
    verifyUrl = response['_embedded']['factors'][factorIndex]['_links']['verify']['href']

    if factorType == "token:software:totp":
        tokenCode = input(mfa[0] + " MFA Code: ")
        payload = {'stateToken': stateToken, 'passCode': tokenCode}
        mfaverify = oktasession.post(verifyUrl, data=json.dumps(payload), headers=headers)
        sessionToken = json.loads(mfaverify.text)['sessionToken']
        status = json.loads(mfaverify.text)['status']
    elif factorType == "push":
        print("Please check OktaVerify app for the push request...")
        payload = {'stateToken': stateToken}
        mfaver = oktasession.post(verifyUrl, data=json.dumps(payload), headers=headers)
        sessionToken = None
        while sessionToken is None:
            temp = oktasession.post(verifyUrl, data=json.dumps(payload), headers=headers)
            verifyStatus = json.loads(temp.text)['status']
            if verifyStatus == 'SUCCESS':
                sessionToken = json.loads(temp.text)['sessionToken']
                status = json.loads(temp.text)['status']
            elif verifyStatus == 'TIMEOUT':
                print("Request for app push timed out. Please try again.")
                sys.exit(1)
            else:
                time.sleep(2)
    elif factorType == "web":
        print("DUO Security is still not supported. Try again with another method.")

    return(status, sessionToken)

if os.name == 'nt':
    username = os.environ['USERNAME']
    basepath = os.environ['USERPROFILE']
else:
    username = os.environ['USER']
    basepath = os.environ['HOME']
    
password = get_password(username)

cli_config_file = basepath + "/.aws/oktacli"
aws_cred_file = basepath + "/.aws/credentials"
profile = sys.argv[1]

cookieJar = {}
headers = {}
payload = {}
conf_dict = {}

creds_dir = os.path.dirname(cli_config_file)
if not os.path.exists(creds_dir):
    os.makedirs(creds_dir)

config = configparser.ConfigParser()
if os.path.isfile(cli_config_file):
    config.read(cli_config_file)
else:
    print("AWS config file not found, please create one with the appropriate profiles")
    sys.exit(1)

# Override the username if we have a different username present
# in the config file. Required by users in Roadster.
if config['user']['user_name']:
    username = config['user']['user_name']

if config['URL']['api']:
    apiUrl = config['URL']['api']
else:
    print("API URL not defined, check your config...")
    sys.exit(1)

if config['URL']['SAML']:
    apiUrl = config['URL']['SAML']
else:
    print("SAML URL not defined, check your config...")
    sys.exit(1)

baseUrl = apiUrl #MINUS STUFF

awscreds = configparser.ConfigParser()
if os.path.isfile(aws_cred_file):
    awscreds.read(aws_cred_file)
if not config.has_section('default'):
    config.add_section('default')

headers['Accept'] = 'application/json'
headers['Content-Type'] = 'application/json'
headers['User-Agent'] = 'Mozilla/5.0 (okta-aws-cli) AppleWebKit/537.36 (okta-aws-cli) Chrome/59.0 Safari/537.36'

oktasession = requests.Session()

url = apiUrl + "/authn"
payload['username'] = username
payload['password'] = password
payload['relayState'] = SAMLurl

login = oktasession.post(url, headers=headers, data=json.dumps(payload))

try:
    status = json.loads(login.text)['status']
except:
    print("Login provided no status due to wrong password.")
    if headless_mode is False:
        print("Updating saved password in keychain...")
        update_password(username)
    sys.exit(1)

if status == "SUCCESS":
    sessionToken = json.loads(login.text)['sessionToken']

elif status == "MFA_REQUIRED":
    stateToken = json.loads(login.content)['stateToken']
    status, sessionToken = do_mfa(json.loads(login.text), payload, stateToken)

elif status != 'SUCCESS':
    print("Unknown error, please retry.")
    sys.exit(1)

url = baseUrl + "/login/sessionCookieRedirect?checkAccountSetupComplete=true&token=" + sessionToken + "&redirectUrl=" + SAMLurl
ckstatus = oktasession.get(url, data=json.dumps(payload), headers=headers)
regex = "((?<=stateToken = \\')\S+(?=\\'))"
match = re.search(regex, ckstatus.text)
stateTokenenc = match.group(0)
if (sys.version_info > (3, 0)):
  stateToken = codecs.escape_decode(bytes(stateTokenenc, "utf-8"))[0].decode("utf-8")
else:
  stateToken = str(codecs.escape_decode(stateTokenenc)[0]).encode('ascii')
payload = {'stateToken': stateToken}
url = apiUrl + "/authn"
reqstatus = oktasession.post(url, data=json.dumps(payload), headers=headers)
response = json.loads(reqstatus.text)
if response['status'] != "MFA_REQUIRED":
    print("Your AWS Okta app does not list a required MFA, please check with your Okta admins.")
    sys.exit(1)
elif response['status'] == "MFA_REQUIRED":
    do_mfa(response, payload, stateToken)

payload = {'stateToken': stateToken}
url = baseUrl + "/login/sessionCookieRedirect?checkAccountSetupComplete=true&token=" + sessionToken + "&redirectUrl=" + SAMLurl
mytest = oktasession.get(url)
sso = oktasession.get(SAMLurl, cookies=cookieJar, headers=headers)
soup = BeautifulSoup(sso.text, "html.parser")
for inputtag in soup.find_all('input'):
    if inputtag.get('name') == 'SAMLResponse':
        assertion = inputtag.get('value')

root = ET.fromstring(base64.b64decode(assertion))
urn = "{urn:oasis:names:tc:SAML:2.0:assertion}"
urn_attribute = urn + "Attribute"
urn_attributevalue = urn + "AttributeValue"
role_url = "https://aws.amazon.com/SAML/Attributes/Role"
role_list = []
for saml2attribute in root.iter(urn_attribute):
    if saml2attribute.get('Name') == role_url:
        for saml2attributevalue in saml2attribute.iter(urn_attributevalue):
            role_list.append(saml2attributevalue.text)

try:
    ledgerRole = config.get(profile, 'ledger_role')
    ledgerPrincipal = config.get(profile, 'ledger_principal')
    arns = [ledgerRole, ledgerPrincipal]
except:
    if len(role_list) > 1:
        arn_text = option_picker(role_list,
                   "You have multiple ledger roles, please select one that has the appropriate permissions to assume the cross-account role:")
    else:
        arn_text = role_list[0]
    arns = arn_text.split(',')

arn_dict = {}
for arn in arns:
    if ":role/" in arn:
        arn_dict['RoleArn'] = arn
    elif ":saml-provider/":
        arn_dict['PrincipalArn'] = arn
arn_dict['SAMLAssertion'] = assertion

sts_client = boto3.client('sts')
response = sts_client.assume_role_with_saml(RoleArn=arn_dict['RoleArn'],
                                            PrincipalArn=arn_dict['PrincipalArn'],
                                            SAMLAssertion=arn_dict['SAMLAssertion'],
                                            DurationSeconds=3600)
aws_temp_cred = response['Credentials']
role_to_assume = config[profile]['role_arn']
config.set(profile, 'ledger_role', arn_dict['RoleArn'])
config.set(profile, 'ledger_principal', arn_dict['PrincipalArn'])

print("Assuming role " + role_to_assume)
RSessionName = username + "-okta-cli"
role_session = boto3.session.Session(
    aws_access_key_id=aws_temp_cred['AccessKeyId'],
    aws_secret_access_key=aws_temp_cred['SecretAccessKey'],
    aws_session_token=aws_temp_cred['SessionToken'])
sts_cli = role_session.client('sts')
xacctcreds = sts_cli.assume_role(
    RoleArn=role_to_assume,
    RoleSessionName=RSessionName,
    DurationSeconds=3600)['Credentials']

# Enable for debug purposes only
# print("AWS temporary creds for profile " + profile)
# print(json.dumps(xacctcreds, indent=4, sort_keys=True, default=str))
if os.name == 'nt':
    print("\n Make sure to enable this profile: 'set AWS_DEFAULT_PROFILE={}'\n".format(profile))
else:
    print("\n Make sure to enable this profile: 'export AWS_DEFAULT_PROFILE={}'\n".format(profile))

if not awscreds.has_section(profile):
    awscreds.add_section(profile)

awscreds.set(profile, 'aws_access_key_id', xacctcreds['AccessKeyId'])
awscreds.set(profile, 'aws_secret_access_key', xacctcreds['SecretAccessKey'])
awscreds.set(profile, 'aws_session_token', xacctcreds['SessionToken'])

with open(aws_cred_file, 'w') as mycreds:
    awscreds.write(mycreds)
with open(cli_config_file, 'w') as myconfig:
    config.write(myconfig)
