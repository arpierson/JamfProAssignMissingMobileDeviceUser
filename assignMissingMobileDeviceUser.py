'''
Created on May 11, 2021

@author: Allen Pierson
'''

import requests

from os.path import expanduser
import xml.etree.ElementTree as ET
import re
import ldap
from xml.dom import minidom
from getpass import getpass


_readAdvancedSearchCredentials = ""
_readWriteMobileDeviceCredentials = ""
_adLoginUser = ""
_adLoginPw = ""


def run():
    '''Main function called to run script
    
    Parameters
    ----------
    None
    
    Returns
    -------
    None
    '''
    
    setApiCredentials()
    devicesWithoutUsers = getMobileDevicesMissingAssignedUsers()
    addUserToDevice(11191) #using hard coded test value for now
    

def setApiCredentials():
    '''Sets global variables _readAdvancedSearchCredentials and _readWriteMobileDeviceCredentials
    
    Prompts user to enter valid Base64 credentials for appropriate Jamf Pro user accounts to be used for API authentication.
    
    Parameters
    ----------
    None
    
    Returns
    -------
    None
    '''
    
    global _readAdvancedSearchCredentials
    global _readWriteMobileDeviceCredentials
    global _adLoginUser
    global _adLoginPw
    
    _adLoginUser = input("Please enter your AD username: ") + "@hcschools.com"
    _adLoginPw = getpass("Please enter your AD password: ")
    _readAdvancedSearchCredentials = getpass("Please enter the Base64 Jamf Pro credential for Mobile Device Advanced Search read access: ")
    _readWriteMobileDeviceCredentials = getpass("Please enter the Base64 Jamf Pro credential for Mobile Device read/write access: ")
    
    
    
def getMobileDevicesMissingAssignedUsers():
    '''Uses Jamf Pro API call to get results of Jamf Pro Advanced Computer Search titled 'Management - District - Computers with blank username' and returns the search result.
    
    Parameters
    ----------
    None
    
    Returns
    -------
    None
    '''
    
    global _readAdvancedSearchCredentials
    url = "https://jamf.hcschools.net:8443/JSSResource/advancedmobiledevicesearches/id/151"
    headers = {'accept': 'application/json', 'authorization': "Basic " + _readAdvancedSearchCredentials}
    searchResult = requests.get(url, headers=headers)
    return searchResult


def addUserToDevice(deviceId):
    url = "https://jamf.hcschools.net:8443/JSSResource/mobiledevices/id/" + str(deviceId)
    headers = {'accept': 'application/xml', 'authorization': "Basic " + _readWriteMobileDeviceCredentials}
    results = requests.get(url, headers=headers).content
    root = ET.fromstring(results)
    
    extensionAttributes = root.find('extension_attributes')
    userNameRegEx = re.compile("N=(.+?),")
    adDistinguishedName = ""
    for attribute in extensionAttributes.findall('extension_attribute'):
        if attribute.find('name').text == "AD Distinguished Name":
            adDistinguishedName = attribute.find('value').text
    
    userFullName = re.search(userNameRegEx, adDistinguishedName).group(1)
    
    adUserAccount = getAdAccountInfo(userFullName)
    adUsername = userFullName.replace(" ", ".")
    adDisplayName = str(adUserAccount[0][1]['displayName'][0].decode('utf-8'))
    adEmailAddress = str(adUserAccount[0][1]['mail'][0].decode('utf-8'))
    
    addUserInfoToXml(results, adUsername, adDisplayName, adEmailAddress)
    
    
def getAdAccountInfo(adUsername):
    '''Looks up an Active Directory account and returns the result.
    
    Parameters
    ----------
    usernameToCheck : str
        A string representing the AD username to be looked up.
        
    Returns
    -------
    str
        Returns the user's displayName and mail attributes.
    '''
    
    global _adLoginUser
    global _adLoginPw
    
    formattedUsernameToCheck = adUsername.replace('HCSCHOOLS\\', '')
    
    conn = ldap.initialize('ldap://172.16.230.21:389')
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    conn.set_option(ldap.OPT_X_TLS_CACERTFILE, "./HCSCHOOLS-ADMASTER-CA.pem")
    conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
    conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
    conn.set_option(ldap.OPT_DEBUG_LEVEL, 255)
    
    base = "DC=HCSCHOOLS, DC=COM"
    criteria1 = "(&(userPrincipalName=" + formattedUsernameToCheck + "@hcschools.com))"
    
    try:
        conn.simple_bind_s(str(_adLoginUser), str(_adLoginPw))
        result = conn.search_s(base, ldap.SCOPE_SUBTREE, criteria1, ['displayName', 'mail'])
        
        if result[0][0] is None:
            cnName = formattedUsernameToCheck.replace(".", " ")
            criteria2 = "(&(cn=" + cnName + "))"
            result = conn.search_s(base, ldap.SCOPE_SUBTREE, criteria2, ['displayName', 'mail'])
        
        if result[0][0] is None:
            return None
        return result
    except ldap.INVALID_CREDENTIALS:
        print("Incorrect AD credentials were entered.")
        exit()
    except ldap.LDAPError as e:
        print("Username " + str(formattedUsernameToCheck) + " threw error " + str(e))
    finally:
        conn.unbind()
    

def addUserInfoToXml(xmlToBeEdited, adUsername, adDisplayName, adEmailAddress):
    root = ET.fromstring(xmlToBeEdited)
    
    for item in root.iter('location'):
        item.find('username').text = adUsername
        item.find('realname').text = adDisplayName
        item.find('real_name').text = adDisplayName
        item.find('email_address').text = adEmailAddress
    
    print(printList(xmlToBeEdited))
    #return xmlToBeEdited


def printList(xmlString):
    root = ET.fromstring(xmlString)
    roughString = ET.tostring(root, 'utf-8')
    reparsed = minidom.parseString(roughString)
    prettyXml = reparsed.toprettyxml(indent="\t")
    print(prettyXml)
    