import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import configparser
import time
import json
import concurrent.futures


logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

crxcavator_api = config['crxcavator']['api']

MAX_THREADS = int(config['crxcavator']['threads'])  # Get max number of threads for multi-threading


class CrXcavator(object):
    def __init__(self, extension_id, version, name):
        self.id = extension_id
        self.version = version
        self.name = name
        self.risk_csp = None
        self.risk_external_javascript = None
        self.risk_external_calls = None
        self.risk_score = 0
        self.entry_points = None
        self.dangerous_functions = None
        self.chrome_link = "https://chrome.google.com/webstore/detail/{0}".format(extension_id)
        self.crxcavator_link = "https://crxcavator.io/report/{0}/{1}".format(extension_id, version)

    def print(self):
        print('ID: %s' % self.id)
        print('Version: %s' % self.version)
        print('Score: %d' % self.risk_score)
        print('Link: %s' % self.chrome_link)
        print('CrXcavator Link: %s' % self.crxcavator_link)
        if self.risk_csp is not None:
            print('CSP: \n%s' % json.dumps(self.risk_csp, indent=2))
        if self.risk_external_javascript is not None:
            print('External JavaScript: \n%s' % json.dumps(self.risk_external_javascript, indent=2))
        if self.risk_external_calls is not None:
            print('External Calls: \n%s' % json.dumps(self.risk_external_calls, indent=2))
        if self.dangerous_functions is not None:
            print('Dangerous Functions: \n%s' % json.dumps(self.dangerous_functions, indent=2))
        if self.entry_points is not None:
            print('Entry Points: \n%s' % json.dumps(self.entry_points, indent=2))
        print()


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    session.headers.update({'API-Key': config['crxcavator']['key'], 'Content-Type': 'application/json'})
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Parse risk data returned from report of crxcavator
def parse_risk_data(extension_id, version, data):
    riskobj = CrXcavator(extension_id, version, data['webstore']['name'])

    if 'csp' in data:
        riskobj.risk_csp = data['csp']

    if 'extjs' in data:
        riskobj.risk_external_javascript = data['extjs']

    if 'extcalls' in data:
        riskobj.risk_external_calls = data['extcalls']

    if 'entrypoints' in data:
        riskobj.entry_points = data['entrypoints']

    if 'dangerousfunctions' in data:
        riskobj.dangerous_functions = data['dangerousfunctions']

    if 'risk' in data:
        for each_item in data['risk']:
            if each_item == 'total' or each_item == 'webstore' or each_item == 'metadata':
                continue
            else:
                riskobj.risk_score = riskobj.risk_score + int(data['risk'][each_item]['total'])
    return riskobj


# Get risk data for a particular extension and their version
def get_extension_risk(extension_id, version):
    risk_obj = None
    session = session_generator()
    resp = session.get("%s/report/%s/%s" % (crxcavator_api, extension_id, version))
    if resp.ok:
        try:
            response = resp.json()
        except json.decoder.JSONDecodeError:
            logger.warning('JSON Decode Error. Retrying for extension %s version %s' % (extension_id, version))
            risk_obj = get_extension_risk(extension_id, version)
            return risk_obj

        if response is None:
            logger.info('Failed to fetch report on %s version %s' % (extension_id, version))
        else:
            if 'version' in response:
                if response['version'] is not None:
                    risk_obj = parse_risk_data(extension_id, response['version'], response['data'])
            else:
                print(json.dumps(response, indent=4))
    elif  600 > resp.status_code >= 500 or resp.status_code == 429:
        logger.warning("Exceed rate limit.")
        time.sleep(60)
        # TO DO:
        # Check header to see if spits out retry.
        # print(resp.header)
        risk_obj = get_extension_risk(extension_id, version)
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        logger.error('Unable to get risk data on extension %s of version %s' % (extension_id, version))
    return risk_obj


# Submit an extension to get it scanned by crxcavator. This would also be useful to classify the extensions to the
# below categories
def submit_extension(extension_id: str):
    submit_results = {}
    submit_results['id'] = extension_id
    submit_results['version'] = None
    submit_results['extension'] = False
    submit_results['not_free'] = False
    submit_results['run_again'] = False
    submit_results['removed_from_store'] = False

    data = {'extension_id': extension_id}
    session = session_generator()
    resp = session.post("%s/submit" % crxcavator_api, json=data)
    if resp.ok:
        try:
            response = resp.json()
        except json.decoder.JSONDecodeError:
            logger.warning('JSON Decode Error. Retrying for extension %s' % extension_id)
            submit_results = submit_extension(extension_id)
            return submit_results

        if 'error' not in response:
            if "no longer in Chrome" in response['message']:
                submit_results['removed_from_store'] = True
            else:
                submit_results['version'] = response['version']
                submit_results['extension'] = True
        else:
            if "not free" in response['error']:
                submit_results['not_free'] = True
            elif "Error retrieving extension from webstore" in response['error']:
                submit_results['run_again'] = True
            elif "Theme" in response['error']:
                submit_results['extension'] = False
            elif 'Error extension is too big' in response['error']:
                submit_results['version'] = ""
                submit_results['extension'] = True
            else:
                logger.error('Extension %s: %s' % (extension_id, response['error']))
    elif resp.status_code == 429:
        logger.warning("Exceed rate limit.")
        time.sleep(60)
        # TO DO:
        # Check header to see if spits out retry.
        # print(resp.header)
        submit_results = submit_extension(extension_id)
    elif 600 > resp.status_code >= 500:
        time.sleep(90)
        logger.error('Server not responsive for extension %s. Trying Again' % extension_id)
        submit_results['run_again'] = True
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
    return submit_results


# Get risk data on multiple versions of the same chrome extension
def fetch_risk_details(extension_id, versions):
    riskobjs = []
    # Check if report exist for current version
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        fs = [executor.submit(get_extension_risk, extension_id, version) for version in versions]
        for future in concurrent.futures.as_completed(fs):
            riskobj = future.result()
            if riskobj is not None:
                riskobjs.append(riskobj)
    return riskobjs
