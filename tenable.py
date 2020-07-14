import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import concurrent.futures
from typing import List, Dict, Tuple
import time
import datetime
import json
import configparser


logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

MAX_THREADS = int(config['tenable']['threads'])  # Get max number of threads for multi-threading

tenable_api = config['tenable']['api']


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    session.headers.update({'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (config['tenable']['id'], config['tenable']['key']), 'Content-Type': 'application/json'})
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Initiate download of all assets
def initiate_export_assets(tag: str, since_days: int) -> str:
    logger.info("Initiating download of %s assets seen in the last %d days" % (tag, since_days))
    uuid = None
    session = session_generator()
    data = {
        "chunk_size": 1000,
        "filters":
            {
                    "last_assessed": int((datetime.datetime.now() - datetime.timedelta(days=since_days)).strftime("%s")),
                    "has_plugin_results": 'true',
                    "tag.Source": tag
            }
    }

    resp = session.post("%s/assets/export" % tenable_api, json=data)
    response = resp.json()
    if resp.ok:
        uuid = response['export_uuid']
    elif resp.status_code == 429:
        logger.warning("Exceed rate limit.")
        time.sleep(60)
        retry_after = int(resp.headers['Retry-After'])
        time.sleep(retry_after)
        uuid = initiate_export_assets(tag, since_days)
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        logger.error('Unable to make rest call to initiate download all %s results' % tag)
    return uuid


# Check if report is ready for download
def check_asset_download_status(uuid: str) -> Tuple[str, List[int]]:
    logger.info("Checking download status of assets for file %s" % uuid)
    session = session_generator()
    status = None
    chunks = []
    resp = session.get("%s/assets/export/%s/status" % (tenable_api, uuid))
    if resp.ok:
        response = resp.json()
        status = response['status']
        if status == 'FINISHED':
            chunks.extend(response['chunks_available'])
    elif resp.status_code == 429:
        logger.warning("Exceed rate limit.")
        retry_after = int(resp.headers['Retry-After'])
        time.sleep(retry_after)
        status, chunks = check_asset_download_status(uuid)
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        logger.error('Unable to make rest call to get status of file download %s' % uuid)
    return status, chunks


def get_all_current_asset_exports(tag: str) -> List[Dict]:
    jobs = []
    logger.info("Fetching running asset export jobs")
    session = session_generator()
    resp = session.get("%s/assets/export/status" % tenable_api)
    if resp.ok:
        response = resp.json()
        for job in response['exports']:
            filters = json.loads(job['filters'])
            if job['status'] == 'PROCESSING' and filters['tag.Source'] == tag and 'has_plugin_results' in filters and 'last_assessed' in filters:
                if 'total_chunks' in job and 'finished_chunks' in job:
                    chunks_left = job['total_chunks'] - job['finished_chunks']
                else:
                    chunks_left = 0
                jobs.append(
                    {
                        'chunks_left': chunks_left,
                        'created': datetime.datetime.utcfromtimestamp(float(job['created'])/1000),
                        'uuid': job['uuid']
                    }

                )
    elif resp.status_code == 429 or 499 < resp.status_code < 600:
        if 'Retry-After' in resp.headers:
            retry_after = int(resp.headers['Retry-After'])
        else:
            retry_after = 90
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        time.sleep(retry_after)
        get_all_current_asset_exports(tag)
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        logger.error('Unable to get rest status of any asset export job')
    return jobs


def check_current_export_status(tag: str):
    logger.info('Checking and killing stuck asset export jobs that over 10 mins')
    asset_export_jobs = {}
    while True:
        jobs = get_all_current_asset_exports(tag)
        if jobs:
            for job in jobs:
                if job['uuid'] not in asset_export_jobs:
                    asset_export_jobs.update({
                        job['uuid']:
                            {
                                'chunks_left': job['chunks_left'],
                                'created': job['created']
                            }
                    })
                    time.sleep(360)
                else:
                    if asset_export_jobs[job['uuid']]['chunks_left'] > job['chunks_left']:
                        asset_export_jobs[job['uuid']]['chunks_left'] = job['chunks_left']
                        time.sleep(360)
                    else:
                        kill_asset_export_job(job['uuid'])
        else:
            break


# Kill Asset Export Job
def kill_asset_export_job(uuid: str):
    logger.info("Killing stuck job %s" % uuid)
    session = session_generator()
    resp = session.post("%s/assets/export/%s/cancel" % (tenable_api, uuid))
    if resp.ok:
        response = resp.json()
        status = response['response']['status']
        if status != 'CANCELLED':
            time.sleep(10)
            kill_asset_export_job(uuid)
    elif resp.status_code == 429 or 499 < resp.status_code < 600:
        if 'Retry-After' in resp.headers:
            retry_after = int(resp.headers['Retry-After'])
        else:
            retry_after = 90
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        time.sleep(retry_after)
        kill_asset_export_job(uuid)
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        logger.error('Unable to kill asset export job %s' % uuid)


def start_and_check_current_asset_export_jobs(tag: str, since_days: int) -> str:
    while True:
        uuid = initiate_export_assets(tag, since_days)
        if uuid is None:
            check_current_export_status(tag)
        else:
            break
    return uuid


# Get all workstation assets based on the matching workstation agents
def download_assets(uuid: str, chunk_id: int) -> List[Dict[str, str]]:
    devices = []
    logger.info("Fetching list of assets for chunk %d" % chunk_id)
    session = session_generator()
    resp = session.get("%s/assets/export/%s/chunks/%d" % (tenable_api, uuid, chunk_id))
    if resp.ok:
        try:
            response = resp.json()
        except json.decoder.JSONDecodeError:
            logger.warning('JSON Decode Error. Retrying for chunk id' % chunk_id)
            devices = download_assets(uuid, chunk_id)
            return devices

        for asset in response:
            if asset['hostnames']:
                device_name = asset['hostnames'][0].replace('\r', '').replace(' ', '').upper()
                if '.' in device_name:
                    device_name = device_name.split('.')[0]
            else:
                device_name = ''

            domains = []
            for dns in asset['fqdns']:
                if 'ip-' != dns[:3]:
                    domains.append(dns.lower())

            if domains:
                domains = list(set(domains))
                if not device_name:
                    for domain in domains:
                        if asset['netbios_names']:
                            if '.' in asset['netbios_names'][0]:
                                device_name = asset['netbios_names'][0].upper().split('.')[0]
                                break
                            elif domain != asset['netbios_names'][0].lower() and asset['netbios_names'][0]:
                                print(domains)
                                print(asset['netbios_names'])
                            else:
                                device_name = domain
                        else:
                            device_name = domain

            if not device_name and asset['netbios_names']:
                device_name = asset['netbios_names'][0].upper().split('.')[0]

            if asset['operating_systems']:
                os = asset['operating_systems'][0].replace('\r', '').replace('-', ' ').capitalize()
            else:
                os = ''

            if '.' in device_name:
                device_name = device_name.split('.')[0].upper()

            if device_name and os:
                device = {
                    'name': device_name,
                    'os': os,
                    'id': asset['id']
                }
                devices.append(device)
    elif resp.status_code == 429:
        #logger.warning("Exceed rate limit.")
        retry_after = int(resp.headers['Retry-After'])
        time.sleep(retry_after)
        devices = download_assets(uuid, chunk_id)
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        logger.error('Unable to make rest call to download assets for chunk %d' % chunk_id)
    return devices


# Extract Extensions from CSV
def extract_chrome_extensions(plugin_output: str, device_name: str) -> Tuple[Dict, Dict, Dict]:
    extension_ids = {}  # Extension ID: Extension Name
    extensions = {}  # Extension ID: Versions list

    chrome_extensions_per_user = {}

    user = ""
    extension_name = ""
    version = ""

    #extensions_to_ignore = ['__MSG_appName__', '__MSG_extName__', '__MSG_APP_NAME__']
    for data in plugin_output.split('\n'):
        if ':' in data and 'User' in data.split(':')[0]:
            user = data.split(': ')[1].lower()
            chrome_extensions_per_user[user] = {}

        if ':' in data and 'Name' in data.split(':')[0]:
            extension_name = data.split(': ')[1]

        #if extension_name in extensions_to_ignore:
        #    continue

        if ':' in data and 'Version' in data.split(':')[0]:
            version = data.split(': ')[1]

        if ':' in data and 'Path' in data.split(':')[0]:
            if '\\' in data:
                path_list = data.split(': ')[1].split('\\')
                id = path_list[len(path_list) - 2]
            else:
                path_list = data.split(': ')[1].split('/')
                id = path_list[len(path_list) - 3]

            if not id.islower() or not len(id) > 30:
                continue

            if extension_name and user and id:
                if user not in chrome_extensions_per_user:
                    chrome_extensions_per_user[user] = {}

                if id in chrome_extensions_per_user[user] and version:
                    chrome_extensions_per_user[user][id]['version'].append(version)
                else:
                    chrome_extensions_per_user[user][id] = {
                        'version': [version],
                        'name': extension_name
                    }

            if id not in extension_ids:
                extension_ids[id] = extension_name

            if id not in extensions:
                extensions[id] = [version]
            else:
                if version not in extensions[id]:
                    extensions[id].append(version)

    if chrome_extensions_per_user:
        chrome_extensions = {
            device_name.upper(): chrome_extensions_per_user
        }
    else:
        chrome_extensions = {}

    return chrome_extensions, extensions, extension_ids


# Get all chrome extensions for each device/asset
def list_chrome_extensions_per_asset(asset, plugin_id, since_days) -> Dict[str, str]:
    chrome_extensions_per_device = {}
    session = session_generator()
    params = {"date_range": str(since_days)}
    resp = session.get("%s/workbenches/assets/%s/vulnerabilities/%d/outputs" % (tenable_api, asset['id'], plugin_id), params=params)
    if resp.ok:
        try:
            response = resp.json()
        except json.decoder.JSONDecodeError:
            logger.warning('JSON Decode Error. Retrying for asset %s' % asset['name'])
            chrome_extensions_per_device = list_chrome_extensions_per_asset(asset, plugin_id, since_days)
            return chrome_extensions_per_device

        if response['outputs']:
            plugin_output = response['outputs'][0]['plugin_output']
            chrome_extensions_per_device[asset['name']] = plugin_output
    elif resp.status_code == 429:
        #logger.warning("Exceed rate limit.")
        retry_after = int(resp.headers['Retry-After'])
        time.sleep(retry_after)
        chrome_extensions_per_device = list_chrome_extensions_per_asset(asset, plugin_id, since_days)
    elif 499 < resp.status_code < 600:
        if 'Retry-After' in resp.headers:
            retry_after = int(resp.headers['Retry-After'])
        else:
            retry_after = 90
        logger.info("Server Error. Retrying in %d seconds" % retry_after)
        time.sleep(retry_after)
        chrome_extensions_per_device = list_chrome_extensions_per_asset(asset, plugin_id, since_days)
    else:
        logger.error('ERROR %s: %s' % (resp.status_code, resp.text))
        logger.error('Unable to make rest call to get chrome extensions for %s' % asset['name'])
    return chrome_extensions_per_device


# Fetch all windows softwares from Tenable since custom days
def get_chrome_extensions(since_days: int) -> Tuple[Dict, Dict, Dict]:
    tenable_workstations = []
    chrome_extensions = {}
    extension_ids_per_version = {}
    extension_ids_per_name = {}

    logger.info('Killing stale jobs > 30 mins')
    jobs = get_all_current_asset_exports('Workstations')
    for job in jobs:
        if (job['created'] + datetime.timedelta(minutes=30)) <= datetime.datetime.now():
            kill_asset_export_job(job['uuid'])

    uuid = start_and_check_current_asset_export_jobs('Workstations', since_days)
    logger.info('Fetching results for Workstations')
    seconds_added = 0

    while True:
        status, chunks = check_asset_download_status(uuid)
        if status == 'FINISHED':
            break
        elif status == 'ERROR':
            uuid = start_and_check_current_asset_export_jobs('Workstations', since_days)
            seconds_added = 0
        else:
            seconds_added = seconds_added + 10
            time.sleep(10)
            if seconds_added > 1000:
                kill_asset_export_job(uuid)
                uuid = start_and_check_current_asset_export_jobs('Workstations', since_days)
                seconds_added = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        fs = [executor.submit(download_assets, uuid, chunk_id) for chunk_id in chunks]
        for future in concurrent.futures.as_completed(fs):
            tenable_workstations.extend(future.result())

    # Extract chrome extensions
    if tenable_workstations:
        windows_workstations = [device for device in tenable_workstations if 'win' in device['os'].lower()]
        mac_workstations = [device for device in tenable_workstations if device['os'] and 'mac' not in device['os'].lower()]
        del tenable_workstations

        chrome_extensions_per_device = {}

        logger.info('Extracting windows chrome extensions for %d assets' % len(windows_workstations))
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            for raw_chrome_extensions in executor.map(lambda asset: list_chrome_extensions_per_asset(asset, 96533, since_days), windows_workstations):
                chrome_extensions_per_device.update(raw_chrome_extensions)
        del windows_workstations

        logger.info('Extracting Mac chrome extensions for %d assets' % len(mac_workstations))
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            for raw_chrome_extensions in executor.map(lambda asset: list_chrome_extensions_per_asset(asset, 133180, since_days), mac_workstations):
                chrome_extensions_per_device.update(raw_chrome_extensions)
        del mac_workstations

        if chrome_extensions_per_device:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                fs = [executor.submit(extract_chrome_extensions, chrome_extensions_per_device[device_name], device_name) for device_name in chrome_extensions_per_device]
                for future in concurrent.futures.as_completed(fs):
                    chrome_extensions_per_device_per_user, extension_ids_per_version_per_device, extension_ids_per_name_per_device = future.result()
                    chrome_extensions.update(chrome_extensions_per_device_per_user)
                    for id in extension_ids_per_version_per_device:
                        if id in extension_ids_per_version:
                            extension_ids_per_version[id].extend(extension_ids_per_version_per_device[id])
                        else:
                            extension_ids_per_version[id] = extension_ids_per_version_per_device[id]
                    extension_ids_per_name.update(extension_ids_per_name_per_device)

            for id in extension_ids_per_version:
                extension_ids_per_version[id] = list(set(extension_ids_per_version[id]))

            del chrome_extensions_per_device

    logger.info('Completed fetching chrome extensions for workstations')
    return chrome_extensions, extension_ids_per_version, extension_ids_per_name
