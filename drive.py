import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import configparser
import json
import logging
import time
import jwt
from typing import Tuple


logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

MAX_THREADS = int(config['drive_sheet']['threads'])
drive_api = config['drive_sheet']['drive_api']

drive_access_tokens = {}


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Create OAuth token per requirement for each recipient
def generate_drive_api_access_token(recipient: str) -> Tuple[str, int]:
    access_token = None
    expiry = None
    jwt_header = {"alg": "RS256", "typ": "JWT"}
    iat = time.time()
    exp = iat + 3600
    jwt_claim_set = {
        'iss': config['drive_sheet']['gcp_project_service_account'],
        'scope': 'https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive.appdata https://www.googleapis.com/auth/drive.readonly',
        'sub': recipient,
        'aud': 'https://www.googleapis.com/oauth2/v4/token',
        'iat': iat,
        'exp': exp
    }
    secret = bytes(config['drive_sheet']['key'].replace('\\n', '\n'), 'utf-8')
    signed_jwt = jwt.encode(jwt_claim_set, secret, headers=jwt_header, algorithm='RS256')
    headers = {"Content-Type": "application/json; charset=utf-8"}
    data = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': signed_jwt.decode('utf-8').replace("'", '"')}
    url = 'https://www.googleapis.com/oauth2/v4/token'
    session = session_generator()
    resp = session.post(url, headers=headers, data=json.dumps(data))
    response = resp.json()
    if resp.ok:
        access_token = response['access_token']
        expiry = time.time() + response['expires_in']
    elif resp.status_code == 429:
        logger.error('Too many requests. Sleeping %s' % response['error_description'])
        time.sleep(1)
        access_token, expiry = generate_drive_api_access_token(recipient)
    elif 499 < resp.status_code < 600:
        logger.error('Server Error. Sleeping 1 second')
        time.sleep(1)
        access_token, expiry = generate_drive_api_access_token(recipient)
    else:
        logger.error('Failed to generate access token')
        logger.error("%d:%s" % (resp.status_code, resp.text))
    return access_token, expiry


def find_drive(drive_name: str, recipient: str) -> str:
    drive_id = None
    access_token = drive_access_tokens[recipient]['access_token']
    expiry = drive_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        url = drive_api.format("drives")
        session = session_generator()
        resp = session.get(url, headers=headers)
        if resp.ok:
            response = resp.json()
            for drive in response['drives']:
                if drive['kind'] == 'drive#drive' and drive['name'] == drive_name:
                    drive_id = drive['id']
        # Rate limiting
        elif resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            drive_id = find_drive(drive_name, recipient)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            drive_id = find_drive(drive_name, recipient)
        else:
            logger.error('Failed to create folder')
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_drive_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            drive_access_tokens[recipient]['access_token'] = access_token
            drive_access_tokens[recipient]['expiry'] = expiry
            drive_id = find_drive(drive_name, recipient)
    return drive_id


def find_item(name: str, recipient: str, driveId: str, search_type: str, parent_id: str = None):
    _id = None
    access_token = drive_access_tokens[recipient]['access_token']
    expiry = drive_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        params = {
            'corpora': 'drive',
            'includeItemsFromAllDrives': True,
            'supportsAllDrives': True,
            'driveId': driveId,
            'fields': 'incompleteSearch,files(id,name,mimeType,parents)'
        }

        if parent_id is None:
            params['q'] = "name = '%s' and trashed = false" % name
        else:
            params['q'] = "name = '%s' and '%s' in parents and trashed = false" % (name, parent_id)

        if search_type == 'folder':
            params['q'] = "%s and mimeType = 'application/vnd.google-apps.folder'" % params['q']
        elif search_type == 'document':
            params['q'] = "%s and mimeType = 'application/vnd.google-apps.document'" % params['q']
        elif search_type == 'sheet':
            params['q'] = "%s and mimeType = 'application/vnd.google-apps.spreadsheet'" % params['q']
        elif search_type == 'presentation':
            params['q'] = "%s and mimeType = 'application/vnd.google-apps.presentation'" % params['q']

        url = drive_api.format("files")
        session = session_generator()
        resp = session.get(url, headers=headers, params=params)
        if resp.ok:
            response = resp.json()
            if response['incompleteSearch']:
                logger.warning('All files/folders are not returned.')
            if response['files']:
                if len(response['files']) == 1:
                    _id = response['files'][0]['id']
                else:
                    logger.warning('Too many folders found with the same name. Aborting search of folder and creating a new folder')
                    for file in response['files']:
                        print(file['name'], ':', file['id'])

        # Rate limiting
        elif resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            _id = find_item(name, recipient, driveId, search_type, parent_id)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            _id = find_item(name, recipient, driveId, search_type, parent_id)
        else:
            logger.error('Failed to find folder %s' % name)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_drive_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            drive_access_tokens[recipient]['access_token'] = access_token
            drive_access_tokens[recipient]['expiry'] = expiry
            _id = find_item(name, recipient, driveId, parent_id)
    return _id


def create_file(filename: str, recipient: str, drive_id: str, file_type: str, parent_folder_id: str = ""):
    if not parent_folder_id:
        parent_folder_id = drive_id
    _id = None
    access_token = drive_access_tokens[recipient]['access_token']
    expiry = drive_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    if file_type == 'folder':
        mimeType = 'application/vnd.google-apps.folder'
    elif file_type == 'document':
        mimeType = 'application/vnd.google-apps.document'
    elif file_type == 'sheet':
        mimeType = 'application/vnd.google-apps.spreadsheet'
    elif file_type == 'presentation':
        mimeType = 'application/vnd.google-apps.presentation'
    else:
        mimeType = 'application/vnd.google-apps.folder'

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        file_metadata = {
            'name': filename,
            'mimeType': mimeType,
            'parents': [parent_folder_id],
            'driveId': drive_id
        }
        url = drive_api.format("files")
        session = session_generator()
        resp = session.post(url, headers=headers, json=file_metadata, params={'supportsAllDrives': True, 'fields': 'id'})
        if resp.ok:
            response = resp.json()
            if 'id' in response and response['id']:
                _id = response['id']
        # Rate limiting
        elif resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            _id = create_file(filename, recipient, drive_id, file_type, parent_folder_id)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            _id = create_file(filename, recipient, drive_id, file_type, parent_folder_id)
        else:
            logger.error('Failed to create file: %s' % filename)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_drive_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            drive_access_tokens[recipient]['access_token'] = access_token
            drive_access_tokens[recipient]['expiry'] = expiry
            _id = create_file(filename, recipient, drive_id, file_type, parent_folder_id)
    return _id


def copy_file(file_id: str, folder_id: str, recipient: str, drive_id: str):
    id = None
    access_token = drive_access_tokens[recipient]['access_token']
    expiry = drive_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        url = drive_api.format("files/%s/copy" % file_id)
        data = {
            'parents[]': [drive_id, folder_id]
        }
        session = session_generator()
        resp = session.post(url, headers=headers, json=data)
        response = resp.json()
        if resp.ok:
            id = response['id']
            # Rate limiting
        elif resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            id = copy_file(file_id, folder_id, recipient, drive_id)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            id = copy_file(file_id, folder_id, recipient, drive_id)
        else:
            logger.error('Failed to copy file: %s' % file_id)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_drive_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            drive_access_tokens[recipient]['access_token'] = access_token
            drive_access_tokens[recipient]['expiry'] = expiry
            id = copy_file(file_id, folder_id, recipient, drive_id)
    return id


def delete_file(file_id: str, recipient: str):
    access_token = drive_access_tokens[recipient]['access_token']
    expiry = drive_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        url = drive_api.format("files/%s" % file_id)
        session = session_generator()
        resp = session.delete(url, headers=headers)
        if resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            delete_file(file_id, recipient)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            delete_file(file_id, recipient)
        elif not resp.ok:
            logger.error('Failed to delete file: %s' % file_id)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_drive_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            drive_access_tokens[recipient]['access_token'] = access_token
            drive_access_tokens[recipient]['expiry'] = expiry
            delete_file(file_id, recipient)
