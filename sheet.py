import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import json
import logging
import time
import jwt
from typing import List, Dict, Tuple
import configparser

logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

MAX_THREADS = int(config['drive_sheet']['threads'])
sheet_api = config['drive_sheet']['sheet_api']

sheet_access_tokens = {}


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Create OAuth token per requirement for each recipient
def generate_sheet_api_access_token(recipient: str) -> Tuple[str, int]:
    access_token = None
    expiry = None
    jwt_header = {"alg": "RS256", "typ": "JWT"}
    iat = time.time()
    exp = iat + 3600
    jwt_claim_set = {
        'iss': config['drive_sheet']['gcp_project_service_account'],
        'scope': 'https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/spreadsheets',
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
        access_token, expiry = generate_sheet_api_access_token(recipient)
    elif 499 < resp.status_code < 600:
        logger.error('Server Error. Sleeping 1 second')
        time.sleep(1)
        access_token, expiry = generate_sheet_api_access_token(recipient)
    else:
        logger.error('Failed to generate access token')
        logger.error("%d:%s" % (resp.status_code, resp.text))
    return access_token, expiry


def create_sheet(filename: str, sheet_content: Dict[str, List[str]], recipient: str, sheet_id: str=None) -> str:
    id = None
    access_token = sheet_access_tokens[recipient]['access_token']
    expiry = sheet_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    sheets = []
    for each_sheet in sheet_content:
        sheet_dict = {'properties': {'title': each_sheet}, 'data': []}
        rows_dict = {'rowData': []}
        for each_row in sheet_content[each_sheet]:
            values = []
            for each_item in each_row:
                value_dict = {'userEnteredValue': {'stringValue': each_item}}
                values.append(value_dict)
            rows_dict['rowData'].append({'values': values})
        sheet_dict['data'].append(rows_dict)
        sheets.append(sheet_dict)

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        data = {
            'sheets': sheets
        }

        if sheet_id is not None:
            data['spreadsheetId'] = sheet_id

        url = sheet_api.format('spreadsheets')
        session = session_generator()
        resp = session.post(url, headers=headers, json=data)
        if resp.ok:
            response = resp.json()
            if 'spreadsheetId' in response:
                id = response['spreadsheetId']
        elif resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            id = create_sheet(filename, sheet_content, recipient, sheet_id)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            id = create_sheet(filename, sheet_content, recipient, sheet_id)
        else:
            logger.error('Failed to create google sheet %s' % filename)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_sheet_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            sheet_access_tokens[recipient]['access_token'] = access_token
            sheet_access_tokens[recipient]['expiry'] = expiry
            id = create_sheet(filename, sheet_content, recipient, sheet_id)
    return id


def new_sheet(filename: str, sheet_id: str, recipient: str, pages: List[str]) -> Dict[str, int]:
    tabs = {}
    access_token = sheet_access_tokens[recipient]['access_token']
    expiry = sheet_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        data = {
            "requests": [],
            'includeSpreadsheetInResponse': True
        }

        for index, page in enumerate(pages):
            data['requests'].append(
                {
                    "addSheet": {
                        "properties": {
                            'title': page,
                            'index': index
                        }
                    }
                }
            )

        url = sheet_api.format('spreadsheets/%s:batchUpdate' % sheet_id)
        session = session_generator()
        resp = session.post(url, headers=headers, json=data)
        if resp.ok:
            response = resp.json()
            for reply in response['replies']:
                tabs[reply['addSheet']['properties']['title']] = reply['addSheet']['properties']['sheetId']
        elif resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            tabs = new_sheet(filename, sheet_id, recipient, pages)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            tabs = new_sheet(filename, sheet_id, recipient, pages)
        else:
            logger.error('Failed to create google sheet in %s' % filename)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_sheet_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            sheet_access_tokens[recipient]['access_token'] = access_token
            sheet_access_tokens[recipient]['expiry'] = expiry
            tabs = new_sheet(filename, sheet_id, recipient, pages)
    return tabs


def append_sheet(filename: str, sheet_content: List[List[str]], recipient: str, sheet_id: str, page_id: int) -> None:
    access_token = sheet_access_tokens[recipient]['access_token']
    expiry = sheet_access_tokens[recipient]['expiry']
    query_start_time = time.time()

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        data = {
            "requests": [
                {
                    'appendCells': {
                        "sheetId": page_id,
                        'fields': '*'
                    }
                }
            ],
            'includeSpreadsheetInResponse': False
        }

        rows = []
        for row in sheet_content:
            column = {
                "values": []
            }

            for cell in row:
                if isinstance(cell, str):
                    column['values'].append(
                        {
                            'userEnteredValue': {
                                'stringValue': cell
                            }
                        }
                    )
                elif isinstance(cell, float):
                    column['values'].append(
                        {
                            'userEnteredValue': {
                                'numberValue': cell
                            },
                            "userEnteredFormat": {
                                'numberFormat': {
                                    'type': 'DATE_TIME',
                                    'pattern': 'yyyy-mm-dd hh:mm:ss.000'
                                }
                            }
                        }
                    )
                elif isinstance(cell, bool):
                    column['values'].append(
                        {
                            'userEnteredValue': {
                                'boolValue': cell
                            }
                        }
                    )
            rows.append(column)

        data['requests'][0]['appendCells']['rows'] = rows

        url = sheet_api.format('spreadsheets/%s:batchUpdate' % sheet_id)
        session = session_generator()
        resp = session.post(url, headers=headers, json=data)
        if resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            append_sheet(filename, sheet_content, recipient, sheet_id, page_id)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            append_sheet(filename, sheet_content, recipient, sheet_id, page_id)
        elif not resp.ok:
            logger.error('Failed to update google sheet %s' % filename)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_sheet_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            sheet_access_tokens[recipient]['access_token'] = access_token
            sheet_access_tokens[recipient]['expiry'] = expiry
            append_sheet(filename, sheet_content, recipient, sheet_id, page_id)


def fetch_contents(sheet_id: str, recipient: str, metadata_only: bool = False) -> Dict:
    access_token = sheet_access_tokens[recipient]['access_token']
    expiry = sheet_access_tokens[recipient]['expiry']
    query_start_time = time.time()
    contents = {}

    # Make the API call if token expiry time is greater than 1 minute
    if (expiry - query_start_time) > 60:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
        url = sheet_api.format('spreadsheets/%s' % sheet_id)
        session = session_generator()
        params = {'includeGridData': True}
        if metadata_only:
            params = {'includeGridData': False}

        resp = session.get(url, headers=headers, params=params)
        if resp.ok:
            response = resp.json()
            if not metadata_only:
                for page in response['sheets']:
                    contents[page['properties']['title']] = []
                    for data in page['data']:
                        rows = data.get('rowData', [])
                        for index, row in enumerate(rows):
                            if index == 0:
                                continue
                            values = []
                            if row:
                                for value in row['values']:
                                    if value.get('formattedValue', ''):
                                        values.append(value['formattedValue'])
                            if values:
                                contents[page['properties']['title']].append(values)
            else:
                for page in response['sheets']:
                    contents[page['properties']['title']] = page['properties']['sheetId']
        elif resp.status_code == 429:
            logger.error('Too many requests. Sleeping %s' % resp.json()['error']['message'])
            time.sleep(1)
            contents = fetch_contents(sheet_id, recipient, metadata_only)
        elif 499 < resp.status_code < 600:
            logger.error('Server Error. Sleeping 1 second')
            time.sleep(1)
            contents = fetch_contents(sheet_id, recipient, metadata_only)
        else:
            logger.error('Failed to fetch contents from google sheet: %s' % sheet_id)
            logger.error("%d:%s" % (resp.status_code, resp.text))
    # Create new access token to be used by the recipient
    else:
        access_token, expiry = generate_sheet_api_access_token(recipient)
        if access_token is not None and expiry is not None:
            sheet_access_tokens[recipient]['access_token'] = access_token
            sheet_access_tokens[recipient]['expiry'] = expiry
            contents = fetch_contents(sheet_id, recipient)
    return contents
