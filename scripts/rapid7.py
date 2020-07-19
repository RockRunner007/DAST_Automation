import requests
import os
import logging
import time
from datetime import date
import json

def configure_logging():
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

def get_project(apikey):
    headers = {
        'X-Api-Key': f"{apikey}"
    }
    payload = {
        #'index': '1',
        #'size': '20',
        'sort': 'scan.name,ASC'        
    }
    resp = requests.get('{URL}/ias/v1/apps', params=payload, headers=headers)

    if resp.status_code == 200:
        logging.info(f"Successfully retrieved apps")
        return resp.json()
    else:
        logging.error(f"Failed to get apps. Status Code: {resp.status_code}")
        exit(1)

def get_scans(apikey, appid):
    headers = {
        'Accept': 'application/json;v=1.0',
        'X-Api-Key': f"{apikey}"
    }
    payload = {
        #'index': '0',
        #'size': '20',
        'sort': 'scan.submit_time,DESC'        
    }
    body = {
        'type':'SCAN',
        'query':f"scan.app.id = '{appid}'"
    }
    resp = requests.post('{URL}/ias/v1/search', params=payload, headers=headers, json=body)
    
    if resp.status_code == 200:
        return resp.json()
    else:
        logging.error(f"Failed to get scans. Status Code: {resp.status_code}")
        exit(1)

def get_searchitems(apikey, severity, appid):
    headers = {
        'Accept': 'application/json;v=1.0',
        'X-Api-Key': f"{apikey}"
    }
    payload = {
        #'index': '0',
        #'size': '20',
        #'sort': 'scan.app.id,ASC'        
    }
    body = {
        'type':'VULNERABILITY',
        'query':f"vulnerability.severity = '{severity}' && vulnerability.app.id = '{appid}'"
    }
    resp = requests.post('{URL}/ias/v1/search', params=payload, headers=headers, json=body)

    if resp.status_code == 200:
        #logging.info(f"Successfully retrieved scans")
        return resp.json()
    else:
        logging.error(f"Failed to complete search. Status Code: {resp.status_code}")
        exit(1)

def main():
    configure_logging()
    apikey = os.environ['jenkinsapikey']    
    project = os.environ['PROJECT_NAME']
    apps = get_project(apikey)

    open('DAST_Results.json', 'a').write("[{")
    for app in apps['data']:
        if app['name'] == project:
            scans = get_scans(apikey,app['id'])

            open('DAST_Results.json', 'a').write(f"'Project':'{app['name']}',")
            if scans['data'] == []:
                open('DAST_Results.json', 'a').write(f"'Lastscandate':'N/A',")
            else:
                open('DAST_Results.json', 'a').write(f"'Lastscandate':'{scans['data'][0]['submit_time']}',")

            highitems = get_searchitems(apikey, 'HIGH', app['id'])
            open('DAST_Results.json', 'a').write(f"'HighSeverity':'{highitems['metadata']['total_data']}',")
                    
            mediumitems = get_searchitems(apikey, 'MEDIUM', app['id'])
            open('DAST_Results.json', 'a').write(f"'MediumSeverity':'{mediumitems['metadata']['total_data']}',")

            lowitems = get_searchitems(apikey, 'LOW', app['id'])
            open('DAST_Results.json', 'a').write(f"'LowSeverity':'{lowitems['metadata']['total_data']}',")

            infoitems = get_searchitems(apikey, 'INFORMATIONAL', app['id'])
            open('DAST_Results.json', 'a').write(f"'InfoSeverity':'{infoitems['metadata']['total_data']}'")
    open('DAST_Results.json', 'a').write("}]")

if __name__ == "__main__":
    main() 
