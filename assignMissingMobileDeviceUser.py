'''
Created on May 11, 2021

@author: Allen Pierson
'''

import requests, re, ldap, base64
import xml.etree.ElementTree as ET
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
    assignUsersToDevices(devicesWithoutUsers)
    

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
    
    _adLoginUser = input("Please enter your AD username: ")
    _adLoginPw = getpass("Please enter your AD password: ")
    jamfProCredentialsBytes = str(_adLoginUser + ":" + _adLoginPw).encode('utf-8')
    jamfProCredentialsBase64 = base64.b64encode(jamfProCredentialsBytes)
    _readAdvancedSearchCredentials = _readWriteMobileDeviceCredentials = jamfProCredentialsBase64.decode('utf-8')
    _adLoginUser += "@hcschools.com"
    
  
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
    headers = {'accept': 'application/xml', 'authorization': "Basic " + _readAdvancedSearchCredentials}
    searchResult = requests.get(url, headers=headers)
    return searchResult


def getAdUserInfo(deviceId, adDistinguishedName):
    '''Looks up a user in Active Directory and returns their AD displayName and mail attributes and the XML data for the iPad to be assigned to the user.
    
    Parameters
    ----------
    deviceId : int
        The Jamf Pro device ID for the device whose XML needs to be retrieved.
    adDistinguishedName : str
        The Distinguished Name attribute of an Active Directory user.
        
    Reeturns
    --------
    adUsername : str
        The Active Directory username of the user.
    adDisplayName : str
        The value of the Active Directory distinguishedName attribute of the user.
    adEmailAddress : str
        The value of the Active Directory email attribute of the user.
    result : requests module result
        Contains the XML data returned from the Jamf Pro API call for a specific mobile device.
    '''
    
    url = "https://jamf.hcschools.net:8443/JSSResource/mobiledevices/id/" + str(deviceId)
    headers = {'accept': 'application/xml', 'authorization': "Basic " + _readWriteMobileDeviceCredentials}
    result = requests.get(url, headers=headers).content
    userNameRegEx = re.compile("N=(.+?),")
    userFullName = re.search(userNameRegEx, adDistinguishedName).group(1)
    adUserAccount = getAdAccountInfo(userFullName)
    
    if adUserAccount != None:
        adUsername = userFullName.replace(" ", ".")
        adDisplayName = str(adUserAccount[0][1]['displayName'][0].decode('utf-8'))
        adEmailAddress = str(adUserAccount[0][1]['mail'][0].decode('utf-8'))
    else:
        print("No AD user found for " + userFullName)
        exit()

    return adUsername, adDisplayName, adEmailAddress, result


def assignUsersToDevices(jamfProAdvancedSearchXml):
    '''Loops through a list of mobile devices, gathers the user Active Directory information and adds it to the XML for a device.
    
    Parameters
    ----------
    jamfProAdvancedSearchXml : requests module result
        Contains the XML returned for the Jamf Pro Advanced Search results.
    
    Returns
    -------
    None
    '''
    
    root = ET.fromstring(jamfProAdvancedSearchXml.content)
    mobileDevicesSubset = root.find('mobile_devices')
    
    for mobileDevice in mobileDevicesSubset.findall('mobile_device'):
        deviceId = mobileDevice.find('id').text
        userAndDeviceInfo = getAdUserInfo(deviceId, mobileDevice.find('AD_Distinguished_Name').text)
        adUsername = userAndDeviceInfo[0]
        adDisplayName = userAndDeviceInfo[1]
        adEmailAddress = userAndDeviceInfo[2]
        deviceXml = userAndDeviceInfo[3]
        
        correctedXml = addUserInfoToXml(deviceXml, adUsername, adDisplayName, adEmailAddress)
         
        result = updateDeviceXml(deviceId, correctedXml.encode('utf-8'))
        
        if result.status_code != 201:
            print("Device ID " + str(deviceId) + " HTTP PUT failed with status code of " + str(result.status_code))
        else:
            print (adUsername + " was succesfully added to device " + str(deviceId) +".")
          
          
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
    '''Takes an XML string, adds the values of parameters 2, 3, and 4 to the appropriate places in the XML, and returns the newly edited XML.
    
    Parameters
    ----------
    xmlToBeEdited : str
        The XML of a mobile device that needs the user information added.
    adUsername : str
        The Active Directory username for the user to be added to the device.
    adDisplayName : str
        The Active Directory displayName for the user to be added to the device.
    adEmailAddress : str
        The Active Directory email address for the user to be added to the device.
        
    Returns
    -------
    ElementTree object, encoded as Unicode, formatted as XML.
    '''
    
    root = ET.fromstring(xmlToBeEdited)
    
    for item in root.iter('location'):
        item.find('username').text = adUsername
        item.find('realname').text = adDisplayName
        item.find('real_name').text = adDisplayName
        item.find('email_address').text = adEmailAddress
    
    return ET.tostring(root, encoding='unicode', method='xml')


def updateDeviceXml(deviceId, xmlToPut):
    '''Takes a Jamf Pro mobile device ID and an XML string and HTTP PUTs the XML string for the device ID.
    
    Parameters
    ----------
    deviceId : int
        The Jamf Pro device ID for the device to be edited.
    xmlToPut : str
        The XML string to be sent to the Jamf Pro API to edit the mobile device.
    
    Returns
    -------
    requests module response object
    '''
    
    global _readWriteMobileDeviceCredentials
    url = "https://jamf.hcschools.net:8443/JSSResource/mobiledevices/id/" + str(deviceId)
    headers = {'content-type': 'application/xml', 'authorization': "Basic " + _readWriteMobileDeviceCredentials}
    return requests.request("PUT", url, headers=headers, data=xmlToPut)
    