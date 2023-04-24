import json
import argparse
import sys
import requests



def get_oauth(client_id: str, client_secret: str, tenant_id: str):
    '''
    get_oauth

    Takes a client id, client secret, and tenant id and returns a valid OAuth token. Will exit program if OAuth is not generated.

    Args:
        client_id: str
            client ID
        client_secret: str
            subscription id
        tenant_id: str
            tenant id
    '''

    oauth_body = {
        # Static, doesn't change
        'grant_type': 'client_credentials',
        # Application (client) ID. Found in the Overview -> Essentials section on your service principal application. Can be found by searching "App registration" in the Azure portal.
        'client_id': client_id,
        # Client Secret. This can ONLY be viewed during initial app creation.
        'client_secret': client_secret,
        # Static. Always this URL for Azure OAuth requests
        'resource': 'https://management.azure.com/'

    }

    # Send the request to OAuth endpoint.
    response = requests.post(f'https://login.microsoftonline.com/{tenant_id}/oauth2/token', data=oauth_body, timeout=300)
    if response.status_code != 200:
        print(f"Error generating OAuth token. See error log below: \n {response.text}")
        return False
    else:
        # Jsonify the response
        response = response.json()

        # Return the access_token from the response to use in subsequent requests
        return response["access_token"]


def create_fusion_rule(workspace: str, subscription_id: str, resource_group: str, rule_id: str, detection):
    '''
    Create_fusion_rule

    Takes a workspace ID, subscription ID, and resource group ID and creates a fusion alert rule within the workspace.

    Returns False if an error occured, True if the rule was successfully created.

    Args:
        workspace: str
            workspace ID
        subscription_id: str
            subscription id
        resource_group: str
            resource group id
        rule_id: str
            rule id
        detection: file
            contents of JSON file passed to program
    '''


    # Need to make our fusion rule data into a JSON object
    fusion_rule_data = json.dumps(detection)


    # Send the request to Azure

    response = requests.put(
        f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}',
        params=parameters,
        headers=headers,
        data=fusion_rule_data,
    )

    if response.status_code not in [200, 201]:
        return_data = {
            "bool": False,
            "data": response.json()
        }
        return return_data
    else:
        return_data = {
            "bool": True,
            "data": response.json()
        }
        return return_data

def create_incident_creation_rule(workspace: str, subscription_id: str, resource_group: str, rule_id: str, detection):
    '''
    create_incident_creation_rule

    Takes a workspace ID, subscription ID, rule ID, resource group, and detection data and creates an incident creation rule within the workspace

    Returns False if an error occured, True is the rule was successfully created.
    Args:
        workspace: str
            workspace ID
        subscription_id: str
            subscription id
        resource_group: str
            resource group id
        rule_id: str
            rule id
        detection: file
            contents of JSON file passed to program

    '''
    # ensure our data is in JSON format
    incident_creation_data = json.dumps(detection)

    # send request to Azure
    response = requests.put(
        f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}',
        params=parameters,
        headers=headers,
        data=incident_creation_data,
    )

    if response.status_code not in [200, 201]:
        return_data = {
            "bool": False,
            "data": response.json()
        }
        return return_data
    else:
        return_data = {
            "bool": True,
            "data": response.json()
        }
        return return_data


def create_scheduled_alert(workspace: str, subscription_id: str, resource_group: str, rule_id: str, detection):
    '''
    Create_scheduled_alert

    Takes a workspace ID, subscription ID, rule id, and resource group ID and creates a scheduled alert within the workspace.

    Returns False if an error occured, True if the rule was successfully created.

    Args:
        workspace: str
            workspace ID
        subscription_id: str
            subscription id
        resource_group: str
            resource group id
        rule_id: str
            rule id
        detection: file
            contents of JSON file passed to program
    '''
    # Data required for a scheduled alert. See https://learn.microsoft.com/en-us/rest/api/securityinsights/stable/alert-rules/create-or-update?tabs=HTTP#creates-or-updates-a-scheduled-alert-rule. for exact definitions

    # Need to make our saved alert data into a JSON
    scheduled_search_data= json.dumps(detection)


    # Send request to Azure

    response = requests.put(
        f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}',
        params=parameters,
        headers=headers,
        data=scheduled_search_data,
    )

    if response.status_code not in [200, 201]:
        return_data = {
            "bool": False,
            "data": response.json()
        }
        return return_data
    else:
        return_data = {
            "bool": True,
            "data": response.json()
        }
        return return_data



def get_alert_details(workspace: str, subscription_id: str, resource_group: str, rule_id: str):
    '''
    Get_alert_details

    Takes a workspace id, subscription id, resource group, and rule id and returns details about the rule.

    Returns information on the rule if it exists, False if it doesnt.

    Args:
        workspace: str
            workspace ID
        subscription_id: str
            subscription id
        resource_group: str
            resource group id
        rule_id: str
            rule id
    '''

    # Really simple, just send a get request with the required data, including the rule id.

    response = requests.get(
        f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}',
        params=parameters,
        headers=headers,
    )
    if response.status_code not in [200, 201]:
        return_data = {
            "bool": False,
            "data": response.json()
        }
        return return_data
    else:
        return_data = {
            "bool": True,
            "data": response.json()
        }
        return return_data



# Global stuff

# Yes, I know this isn't a great practice. Who cares.

# Create headers that contain our OAuth token
headers = {
    "Authorization": '',
    'Content-Type': 'application/json'
}

# Make sure to send the API version to the endpoint. IDK why Azure still does this in 2023.
parameters = {
    'api-version': '2022-11-01'
}

if __name__ == "__main__":

    # Boilerplate commandline for python

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--tenant_id", type=str, required=True)
    parser.add_argument("-c", "--client_id", type=str, required=True)
    parser.add_argument("-s", "--client_secret", type=str, required=True)
    parser.add_argument("-b", "--subscription_id", type=str, required=True)
    parser.add_argument("-w", "--workspace_id", type=str, required=True)
    parser.add_argument("-g", "--resource_group", type=str, required=True)
    parser.add_argument("-j", "--json", type=argparse.FileType('r'), required=False)
    parser.add_argument("-r", "--run", type=str, required=True,choices=["fusion", "alert", "details"])
    parser.add_argument("-u", "--rule_id", type=str, required=True)
    args = parser.parse_args()

    if args.run not in ["fusion", "alert", "details"]:
        print(f"{args.run} is not an option for -r or --run. Available options are \"fusion\", \"alert\", or \"details\"")
        sys.exit(1)

    oauth_token = get_oauth(args.client_id, args.client_secret, args.tenant_id)

    # if we can't get our OAUTH token, exit
    if oauth_token is False:
        print("Couldn't get OAUTH token. Please check your credentials and permissions.")
        sys.exit(1)

    headers.update({"Authorization": f"Bearer {oauth_token}"})

    # convert detection json file back to JSON

    data = json.loads(args.json.read())

    # If the user specifies the creation of a fusion rule
    if args.run == "fusion":
        response_data = create_fusion_rule(args.workspace_id, args.subscription_id, args.resource_group, args.rule_id, data)
    # If the user specifies the creation of a saved alert
    elif args.run == "alert":
        response_data = create_scheduled_alert(args.workspace_id, args.subscription_id, args.resource_group, args.rule_id, data)
    # If the user specifices getting the details of an alert
    elif args.run == "details":
        response_data = get_alert_details(args.workspace_id, args.subscription_id, args.resource_group, args.rule_id)

    if response_data["bool"] is False:
        print(f"Error with creating rule/fusion alert. See error log below:\n {response_data}")
    else:
        print(f"Operation Successful. See details below:\n {response_data}")
