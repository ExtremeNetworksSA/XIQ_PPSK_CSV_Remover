#!/usr/bin/env python3
import json
import requests
import logging
import os
import getpass
import pandas as pd
import numpy as np
from pprint import pprint


####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         26th May 2025
# version:      2.0.0
####################################


# Global Variables - ADD CORRECT VALUES
filename = "PPSK_Users.csv"

#XIQ MaxPageSize (max is 100)
pageSize = 100

#print("Enter your XIQ login credentials")
#XIQ_username = input("Email: ")
#XIQ_password = getpass.getpass("Password: ")
####OR###
## TOKEN permission needs - enduser,pcg:key
XIQ_token = "****"

group_roles = {
    # User Group Name, XIQ group ID
    "User Group Name 1": "XIQ group 1 ID",
    "User Group Name 2": "XIQ group 2 ID"
}

PCG_Enable = False

PCG_Mapping = {
    "XIQ User Group ID" : {
        "UserGroupName": "XIQ User Group Name",
        "policy_id": "Network Policy ID associated with PCG",
         "policy_name": "Network Policy name associated with PCG"
    }
}

#-------------------------
# logging
PATH = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
    filename='{}/XIQ_PPSK_CSV_Remover.log'.format(PATH),
    filemode='a',
    level=os.environ.get("LOGLEVEL", "INFO"),
    format= '%(asctime)s: %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
)

URL = "https://api.extremecloudiq.com"
headers = {"Accept": "application/json", "Content-Type": "application/json"}

def getAccessToken(XIQ_username, XIQ_password):
    url = URL + "/login"
    payload = json.dumps({"username": XIQ_username, "password": XIQ_password})
    response = requests.post(url, headers=headers, data=payload)
    if response is None:
        log_msg = "ERROR: Not able to login into ExtremeCloudIQ - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    if response.status_code != 200:
        log_msg = f"Error getting access token - HTTP Status Code: {str(response.status_code)}"
        logging.error(f"{log_msg}")
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)
    data = response.json()

    if "access_token" in data:
        #print("Logged in and Got access token: " + data["access_token"])
        headers["Authorization"] = "Bearer " + data["access_token"]
        return 0

    else:
        log_msg = "Unknown Error: Unable to gain access token"
        logging.warning(log_msg)
        raise TypeError(log_msg)

def retrievePPSKUsers(usergroupID):
    page = 1
    pageCount = 1
    firstCall = True

    ppskUsers = []

    while page <= pageCount:
        url = URL + "/endusers?page=" + str(page) + "&limit=" + str(pageSize) + "&user_group_ids=" + usergroupID

        # Get the next page of the ppsk users
        response = requests.get(url, headers=headers, verify = True)
        if response is None:
            log_msg = "Error retrieving PPSK users from XIQ - no response!"
            logging.error(log_msg)
            raise TypeError(log_msg)

        elif response.status_code != 200:
            log_msg = f"Error retrieving PPSK users from XIQ - HTTP Status Code: {str(response.status_code)}"
            logging.error(log_msg)
            logging.warning(f"\t\t{response.json()}")
            raise TypeError(log_msg)

        rawList = response.json()
        ppskUsers = ppskUsers + rawList['data']

        if firstCall == True:
            pageCount = rawList['total_pages']
        print(f"completed page {page} of {rawList['total_pages']} collecting PPSK Users")
        page = rawList['page'] + 1 
    return ppskUsers

def deleteUser(userId):
    url = URL + "/endusers/" + str(userId)
    
    response = requests.delete(url, headers=headers, verify=True)
    if response is None:
        log_msg = f"Error deleting PPSK user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Error deleting PPSK user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)
    elif response.status_code == 200:
        return 'Success', str(userId)

def retrievePCGUsers(policy_id):
    page = 1
    pageCount = 1
    firstCall = True

    PCGUsers = []

    while page <= pageCount:
        url = URL + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users?page=" + str(page) + "&limit=" + str(pageSize)
        response = requests.get(url, headers=headers, verify = True)
        if response is None:
            log_msg = f"Error retrieving PCG users for policy id {policy_id} from XIQ - no response!"
            logging.error(log_msg)
            raise TypeError(log_msg)
        elif response.status_code != 200:
            log_msg = f"Error retrieving PCG users for policy id {policy_id} from XIQ - HTTP Status Code: {str(response.status_code)}"
            logging.error(log_msg)
            logging.warning(f"\t\t{response.json()}")
            raise TypeError(log_msg)
        
        rawList = response.json()
        PCGUsers = PCGUsers + rawList['data']
        if firstCall == True:
            pageCount = rawList['total_pages']
        print(f"completed page {page} of {rawList['total_pages']} collecting PCG Users for policy id {policy_id}")
        page = rawList['page'] + 1
    return PCGUsers

def deletePCGUsers(policy_id, userId):
    url = URL + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    payload = json.dumps({
                    "user_ids": [
                                    userId
                                ]
                })
    response = requests.delete(url, headers=headers, data=payload, verify = True)
    if response is None:
        log_msg = f"Error deleting PCG user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 202:
        log_msg = f"Error deleting PCG user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)
    elif response.status_code == 202:
        return 'Success'

def main():
    ##  load CSV file   ##
    if os.path.isfile(PATH + '/' + filename):
        try:
            df = pd.read_csv(PATH + '/' + filename)
        except:
            print(f"failed to load file {filename}")
            print("script exiting....")
            raise SystemExit
    else:
        print(f"The file {filename} was not in {PATH}")
        print("script exiting....")
        raise SystemExit

    
    df = df.replace(np.nan,"")
    ## Get token for Main Account ##
    if not XIQ_token:
        try:
            login = getAccessToken(XIQ_username, XIQ_password)
        except TypeError as e:
            print(e)
            raise SystemExit
        except:
            log_msg = "Unknown Error: Failed to generate token"
            logging.error(log_msg)
            print(log_msg)
            raise SystemExit  
    else:
        headers["Authorization"] = "Bearer " + XIQ_token 
    
    ListOfXIQUserGroups = group_roles.values()

    # Collect PSK users
    ppsk_users = []
    for usergroupID in ListOfXIQUserGroups:
        try:
            ppsk_users += retrievePPSKUsers(usergroupID)
        except TypeError as e:
            print(e)
            print("script exiting....")
            # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            raise SystemExit
        except:
            log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
            logging.error(log_msg)
            print(log_msg)
            print("script exiting....")
            # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            raise SystemExit
    log_msg = ("Successfully parsed " + str(len(ppsk_users)) + " XIQ users")
    logging.info(log_msg)
    print(f"\n{log_msg}")
    
    if PCG_Enable == True:
        pcg_capture_success = True
        # Collect PCG Users if PCG is Enabled
        PCGUsers = []
        policy_name = list(set([PCG_Mapping[x]['policy_name'] for x in PCG_Mapping]))
        group_ids = []
        for x in PCG_Mapping:
            if PCG_Mapping[x]['policy_name'] in policy_name:
                group_ids.append(x)
                policy_name.remove(PCG_Mapping[x]['policy_name'])
        for group_id in group_ids:
            policy_id = PCG_Mapping[group_id]['policy_id']
            try:
                PCGUsers += retrievePCGUsers(policy_id)
            except TypeError as e:
                print(e)
                pcg_capture_success = False
            except:
                log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
                logging.error(log_msg)
                print(log_msg)
                pcg_capture_success = False
        log_msg = "Successfully parsed " + str(len(PCGUsers)) + " PCG users"
        logging.info(log_msg)
        print(f"{log_msg}\n")

     # Track Error counts
    ppsk_del_error = 0
    pcg_del_error = 0

    # Delete CSV Users 
    for index, row in df.iterrows():
        if row['User Group Name'] not in group_roles.keys():
            msg = (f"{row['User Group Name']} group name for CSV user {row['User Name']} is not configured in the script.")
            logging.warning(msg)
            print(msg)
            print("Skipping User...")
            continue
        else:
            user_group_id = group_roles[row['User Group Name']]
        if not any(d['user_name'] == row['User Name'] for d in ppsk_users):
            print(f"User {row['User Name']} not found in XIQ...")
        else:
            if PCG_Enable == True and str(user_group_id) in PCG_Mapping:
                if pcg_capture_success == False:
                    log_msg = f"Due to PCG read failure, user {row['User Name']} cannot be deleted"
                    logging.error(log_msg)
                    print(log_msg)
                    ppsk_del_error+=1
                    pcg_del_error+=1
                    continue
                # If PCG is Enabled, Users need to be deleted from PCG group before they can be deleted from User Group
                if any(d['email'] == row['Email'] for d in PCGUsers):
                    # Find specific PCG user and get the user id
                    PCGUser = (list(filter(lambda PCGUser: PCGUser['email'] == row['Email'], PCGUsers)))[0]
                    pcg_id = PCGUser['id']
                    for PCG_Map in PCG_Mapping.values():
                        if PCG_Map['UserGroupName'] == PCGUser['user_group_name']:
                            policy_id = PCG_Map['policy_id']
                            policy_name = PCG_Map['policy_name']
                    result = ''
                    try:
                        result = deletePCGUsers(policy_id, pcg_id)
                    except TypeError as e:
                        logmsg = f"Failed to delete user {row['User Name']} from PCG group {policy_name} with error: {e}"
                        logging.error(logmsg)
                        print(logmsg)
                        ppsk_del_error+=1
                        pcg_del_error+=1
                        continue
                    except:
                        log_msg = f"Unknown Error: Failed to delete user {row['User Name']} from pcg group {policy_name}"
                        logging.error(log_msg)
                        print(log_msg)
                        ppsk_del_error+=1
                        pcg_del_error+=1
                        continue
                    if result == 'Success':
                        log_msg = f"User {row['User Name']} - {pcg_id} was successfully deleted from pcg group {policy_name}."
                        logging.info(log_msg)
                        print(log_msg)
                    else:
                        log_msg = f"User {row['User Name']} - {pcg_id} was not successfully deleted from pcg group {policy_name}. User cannot be deleted from the PCG Group."
                        logging.info(log_msg)
                        print(log_msg)
                        ppsk_del_error+=1
                        pcg_del_error+=1 
                        continue
            result = ''
            ## Delete PPSK user ##
            try:
                PPSKUser = (list(filter(lambda PPSKUser: PPSKUser['email_address'] == row['Email'], ppsk_users)))[0]
            except IndexError:
                log_msg = f"User {row['User Name']}'s email address '{row['Email']}' was not found in XIQ PPSK users list."
                logging.error(log_msg)
                print(log_msg)
                ppsk_del_error+=1
                continue
            try:
                result, userid = deleteUser(PPSKUser['id'])
            except TypeError as e:
                logmsg = f"Failed to delete user {row['User Name']}  with error {e}"
                logging.error(logmsg)
                print(logmsg)
                continue
            except:
                log_msg = f"Unknown Error: Failed to create user {row['User Name']} "
                logging.error(log_msg)
                print(log_msg)
                continue
            if result == 'Success':
                log_msg = f"User {row['User Name']} - {userid} was successfully deleted from PPSK Group."
                logging.info(log_msg)
                print(log_msg)  

    if ppsk_del_error:
        log_msg = f"There were {ppsk_del_error} errors deleting PPSK users on this run."
        logging.info(log_msg)
        print(log_msg)
    if pcg_del_error:
        log_msg = f"There were {pcg_del_error} errors deleting PCG users on this run."
        logging.info(log_msg)
        print(log_msg)

    
        
if __name__ == '__main__':
	main()