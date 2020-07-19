import json
import requests
import os
import logging
import sys
from datetime import datetime, timedelta, timezone

def configure_logging():
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

def _set_headers(apikey):
    headers = {
        'X-Api-Key': f"{apikey}"
    }
    return headers

def process_api_request(url: str, verb: str, headers: dict, data: dict = None, params: dict = None):
    try:
        if data: r = getattr(requests, verb.lower())(url,headers=headers,data=json.dumps(data))
        elif params: r = getattr(requests, verb.lower())(url,headers=headers,params=json.dumps(params))
        else: r = getattr(requests, verb.lower())(url,headers=headers)

        r.raise_for_status()
    except Exception as e:
        logging.error(f'An error occured executing the API call: {e}')

    try:
        return r.json()
    except Exception as e:
        logging.error(f'An error occured loading the content: {e}')
        return None

def get_project(apikey):    
    params = {
        #'index': '1',
        #'size': '20',
        'sort': 'scan.name,ASC'        
    }
    return process_api_request('https://us.api.insight.rapid7.com/ias/v1/apps', 'GET', _set_headers(apikey), params=params)

def get_scans(apikey, appid):
    params = {
        #'index': '0',
        #'size': '20',
        'sort': 'scan.submit_time,DESC'        
    }
    json = {
        'type':'SCAN',
        'query':f"scan.app.id = '{appid}'"
    }
    resp = requests.post('https://us.api.insight.rapid7.com/ias/v1/search', params=params, headers=_set_headers(apikey), json=json)
    
    if resp.status_code == 200:
        return resp.json()
    else:
        logging.error(f"Failed to get scans. Status Code: {resp.status_code}")
        sys.exit(1)

def format_json(project, scandate, scancount):
    with open('scans.json', 'a') as f:
        if scancount > 0: f.write(",")
        f.write(f"{chr(123)}{chr(34)}Product{chr(34)}: {chr(34)}{project}{chr(34)}, {chr(34)}Last Scan{chr(34)}: {chr(34)}{scandate}{chr(34)}{chr(125)}")            
    return ""

def main():
    configure_logging()
    apikey = os.environ['apikey']
    cutoff_time = datetime.now() - timedelta(days=int(os.environ['TIMEFRAME']))
    scancount = 0 
    
    with open('scans.json', 'a') as f: f.write("[")
    
    projects = get_project(apikey)
    for app in projects['data']:
        scans = get_scans(apikey,app['id'])
        
        if scans['data'] == []:
            format_json(app['name'], 'N/A', scancount)
        else:
            scandate = scans['data'][0]['submit_time'].split("T")[0]
            if (datetime.fromisoformat(scandate) < cutoff_time):
                format_json(app['name'], scandate, scancount)
        scancount +=1
    
    with open('scans.json', 'a') as f: f.write("]")

if __name__ == "__main__":
    main()