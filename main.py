import crxcavator
import logging
import tenable
import concurrent.futures
import json
import sheet
import time
import drive
from datetime import datetime
import click
from math import ceil
import configparser

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-15s [%(levelname)-8s]: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

gsuite_service_account = config['drive_sheet']['gsuite_service_account']
team_drive = config['drive_sheet']['team_drive']

MAX_THREADS = 5  # Get max number of threads for multi-threading


class RiskyExtensions(crxcavator.CrXcavator):
    def __init__(self, extension_id, version):
        super(RiskyExtensions, self).__init__(extension_id, version)
        self.name = None
        self.users = []
        self.devices = []


def create_report_risky_extensions(risky_extensions, filename, file_id, sheet_id):
    extensions = ['Name,ID,Version,CrxCavatorv Link,Chrome Link,Devices,Number of Devices,Users,Number of Users,Score,CSP,External JS,External Call,Dangerous Functions,Entry Points'.split(',')]
    for id in risky_extensions:
        for version in risky_extensions[id]:
            if risky_extensions[id][version].users:
                dangerous_funcs = {}
                if risky_extensions[id][version].dangerous_functions:
                    for key in risky_extensions[id][version].dangerous_functions:
                        dangerous_funcs[key] = list(risky_extensions[id][version].dangerous_functions[key].keys())

                sheet_row = [
                    risky_extensions[id][version].name,
                    id,
                    version,
                    risky_extensions[id][version].crxcavator_link,
                    risky_extensions[id][version].chrome_link,
                    ';'.join(risky_extensions[id][version].devices),
                    str(len(risky_extensions[id][version].devices)),
                    ';'.join(risky_extensions[id][version].users),
                    str(len(risky_extensions[id][version].users)),
                    str(risky_extensions[id][version].risk_score),
                    json.dumps(risky_extensions[id][version].risk_csp, indent=2),
                    json.dumps(risky_extensions[id][version].risk_external_javascript, indent=2),
                    json.dumps(risky_extensions[id][version].risk_external_calls, indent=2),
                    json.dumps(dangerous_funcs, indent=2),
                    json.dumps(risky_extensions[id][version].entry_points, indent=2)
                ]

                char_length = 0
                if len(';'.join(risky_extensions[id][version].users)) > 49000:
                    char_length = len(';'.join(risky_extensions[id][version].users))

                if len(';'.join(risky_extensions[id][version].devices)) > 49000 and len(';'.join(risky_extensions[id][version].devices)) > char_length:
                    char_length = len(';'.join(risky_extensions[id][version].devices))

                if len(json.dumps(risky_extensions[id][version].risk_external_calls, indent=2)) > 49000 and len(json.dumps(risky_extensions[id][version].risk_external_calls, indent=2)) > char_length:
                    char_length = len(json.dumps(risky_extensions[id][version].risk_external_calls, indent=2))

                users_list = []
                device_list = []
                _list = []

                if len(json.dumps(risky_extensions[id][version].risk_external_calls, indent=2)) > 49000:
                    number_in_each_block_list = ceil(len(risky_extensions[id][version].risk_external_calls) / ceil(char_length / 45000))
                    _list = [risky_extensions[id][version].risk_external_calls[i:i + number_in_each_block_list] for i in range(0, len(risky_extensions[id][version].risk_external_calls), number_in_each_block_list)]

                if len(';'.join(risky_extensions[id][version].users)) > 49000:
                    number_in_each_user_block_list = ceil(len(risky_extensions[id][version].users) / ceil(char_length / 45000))
                    users_list = [risky_extensions[id][version].users[i:i + number_in_each_user_block_list] for i in range(0, len(risky_extensions[id][version].users), number_in_each_user_block_list)]

                if len(';'.join(risky_extensions[id][version].devices)) > 49000:
                    number_in_each_device_block_list = ceil(len(risky_extensions[id][version].devices) / ceil(char_length / 45000))
                    device_list = [risky_extensions[id][version].devices[i:i + number_in_each_device_block_list] for i in range(0, len(risky_extensions[id][version].devices), number_in_each_device_block_list)]

                if users_list or device_list or _list:
                    if users_list:
                        for index, users in enumerate(users_list):
                            sheet_row[7] = ';'.join(users)
                            sheet_row[8] = str(len(users))
                            if device_list:
                                try:
                                    sheet_row[5] = ';'.join(device_list[index])
                                    sheet_row[6] = str(len(device_list[index]))
                                except IndexError:
                                    sheet_row[5] = ''
                                    sheet_row[6] = ''
                            if _list:
                                try:
                                    sheet_row[12] = json.dumps(_list[index], indent=2)
                                except IndexError:
                                    sheet_row[12] = ''
                            extensions.append(sheet_row)
                    elif device_list:
                        for index, devices in enumerate(device_list):
                            sheet_row[5] = ';'.join(devices)
                            sheet_row[6] = str(len(devices))
                            if _list:
                                try:
                                    sheet_row[12] = json.dumps(_list[index], indent=2)
                                except IndexError:
                                    sheet_row[12] = ''
                            extensions.append(sheet_row)
                    elif _list:
                        for function_list in _list:
                            sheet_row[12] = json.dumps(function_list, indent=2)
                            extensions.append(sheet_row)
                else:
                    extensions.append(sheet_row)

    logger.info('Updating spreadsheet %s in %s drive with data for Risky Chrome Extensions' % (filename, team_drive))
    sheet.append_sheet(filename, extensions, gsuite_service_account, file_id, sheet_id)


def create_report_unscanned_paid_extensions(paid_extensions, filename, file_id, sheet_id):
    extensions = ['Name,ID,Version,Chrome Link,Devices,Number of Devices,Users,Number of Users'.split(',')]
    for id in paid_extensions:
        for version in paid_extensions[id]:
            if version == 'id':
                continue

            sheet_row = [
                paid_extensions[id]['name'],
                id,
                version,
                "https://chrome.google.com/webstore/detail/{0}".format(id),
                ';'.join(paid_extensions[id][version]['devices']),
                str(len(paid_extensions[id][version]['devices'])),
                ';'.join(paid_extensions[id][version]['users']),
                str(len(paid_extensions[id][version]['users']))
            ]

            char_length = 0
            if len(';'.join(paid_extensions[id][version]['users'])) > 49000:
                char_length = len(';'.join(paid_extensions[id][version]['users']))

            if len(';'.join(paid_extensions[id][version]['devices'])) > 49000 and len(';'.join(paid_extensions[id][version]['devices'])) > char_length:
                char_length = len(';'.join(paid_extensions[id][version]['devices']))

            users_list = []
            device_list = []

            if len(';'.join(paid_extensions[id][version]['users'])) > 49000:
                number_in_each_user_block_list = ceil(len(paid_extensions[id][version]['users']) / ceil(char_length / 45000))
                users_list = [paid_extensions[id][version]['users'][i:i + number_in_each_user_block_list] for i in range(0, len(paid_extensions[id][version]['users']), number_in_each_user_block_list)]

            if len(';'.join(paid_extensions[id][version]['devices'])) > 49000:
                number_in_each_device_block_list = ceil(len(paid_extensions[id][version]['devices']) / ceil(char_length / 45000))
                device_list = [paid_extensions[id][version]['devices'][i:i + number_in_each_device_block_list] for i in range(0, len(paid_extensions[id][version]['devices']), number_in_each_device_block_list)]

            if users_list or device_list:
                if users_list:
                    for index, users in enumerate(users_list):
                        sheet_row[6] = ';'.join(users)
                        sheet_row[7] = str(len(users))
                        if device_list:
                            try:
                                sheet_row[4] = ';'.join(device_list[index])
                                sheet_row[5] = str(len(device_list[index]))
                            except IndexError:
                                sheet_row[4] = ''
                                sheet_row[5] = ''
                        extensions.append(sheet_row)
                elif device_list:
                    for index, devices in enumerate(device_list):
                        sheet_row[4] = ';'.join(devices)
                        sheet_row[5] = str(len(devices))
                        extensions.append(sheet_row)
            else:
                extensions.append(sheet_row)

    logger.info('Updating spreadsheet %s in %s drive with data for Unscanned Paid Chrome Extensions' % (filename, team_drive))
    sheet.append_sheet(filename, extensions, gsuite_service_account, file_id, sheet_id)


def create_report_removed_from_store(extensions_removed_from_chrome_store, filename, file_id, sheet_id):
    extensions = ['Name,ID,Version,Chrome Link,Devices,Number of Devices,Users,Number of Users'.split(',')]
    for id in extensions_removed_from_chrome_store:
        for version in extensions_removed_from_chrome_store[id]:
            if version == 'id':
                continue

            sheet_row = [
                extensions_removed_from_chrome_store[id]['name'],
                id,
                version,
                "https://crxcavator.io/report/{0}/{1}".format(id, version),
                ';'.join(extensions_removed_from_chrome_store[id][version]['devices']),
                str(len(extensions_removed_from_chrome_store[id][version]['devices'])),
                ';'.join(extensions_removed_from_chrome_store[id][version]['users']),
                str(len(extensions_removed_from_chrome_store[id][version]['users']))
            ]

            char_length = 0
            if len(';'.join(extensions_removed_from_chrome_store[id][version]['users'])) > 49000:
                char_length = len(';'.join(extensions_removed_from_chrome_store[id][version]['users']))

            if len(';'.join(extensions_removed_from_chrome_store[id][version]['devices'])) > 49000 and len(';'.join(extensions_removed_from_chrome_store[id][version]['devices'])) > char_length:
                char_length = len(';'.join(extensions_removed_from_chrome_store[id][version]['devices']))

            users_list = []
            device_list = []

            if len(';'.join(extensions_removed_from_chrome_store[id][version]['users'])) > 49000:
                number_in_each_user_block_list = ceil(len(extensions_removed_from_chrome_store[id][version]['users']) / ceil(char_length / 45000))
                users_list = [extensions_removed_from_chrome_store[id][version]['users'][i:i + number_in_each_user_block_list] for i in range(0, len(extensions_removed_from_chrome_store[id][version]['users']), number_in_each_user_block_list)]

            if len(';'.join(extensions_removed_from_chrome_store[id][version]['devices'])) > 49000:
                number_in_each_device_block_list = ceil(len(extensions_removed_from_chrome_store[id][version]['devices']) / ceil(char_length / 45000))
                device_list = [extensions_removed_from_chrome_store[id][version]['devices'][i:i + number_in_each_device_block_list] for i in range(0, len(extensions_removed_from_chrome_store[id][version]['devices']), number_in_each_device_block_list)]

            if users_list or device_list:
                if users_list:
                    for index, users in enumerate(users_list):
                        sheet_row[6] = ';'.join(users)
                        sheet_row[7] = str(len(users))
                        if device_list:
                            try:
                                sheet_row[4] = ';'.join(device_list[index])
                                sheet_row[5] = str(len(device_list[index]))
                            except IndexError:
                                sheet_row[4] = ''
                                sheet_row[5] = ''
                        extensions.append(sheet_row)
                elif device_list:
                    for index, devices in enumerate(device_list):
                        sheet_row[4] = ';'.join(devices)
                        sheet_row[5] = str(len(devices))
                        extensions.append(sheet_row)
            else:
                extensions.append(sheet_row)

    logger.info('Updating spreadsheet %s in %s drive with data for Chrome Extensions Removed from Store' % (filename, team_drive))
    sheet.append_sheet(filename, extensions, gsuite_service_account, file_id, sheet_id)


def create_report_no_version_extension(version_not_scanned_in_crxcavator, filename, file_id, sheet_id):
    extensions = ['Name,ID,Version,Version Scanned in Crxcavator,Chrome Link,Devices,Number of Devices,Users,Number of Users,Score,CSP,External JS,External Call,Dangerous Functions,Entry Points'.split(',')]
    for id in version_not_scanned_in_crxcavator:
        for version in version_not_scanned_in_crxcavator[id]:
            if version == 'id' or version == 'latest_version' or version == 'risk_associated_with_latest_version':
                continue

            if not version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version']:
                sheet_row = [
                    version_not_scanned_in_crxcavator[id]['name'],
                    id,
                    version,
                    version_not_scanned_in_crxcavator[id]['latest_version'],
                    "https://chrome.google.com/webstore/detail/{0}".format(id),
                    ';'.join(version_not_scanned_in_crxcavator[id][version]['devices']),
                    str(len(version_not_scanned_in_crxcavator[id][version]['devices'])),
                    ';'.join(version_not_scanned_in_crxcavator[id][version]['users']),
                    str(len(version_not_scanned_in_crxcavator[id][version]['users'])),
                    '',
                    '',
                    '',
                    '',
                    '',
                    ''
                ]
            else:
                dangerous_funcs = {}
                if version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].dangerous_functions:
                    for key in version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].dangerous_functions:
                        dangerous_funcs[key] = list(version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].dangerous_functions[key].keys())

                sheet_row = [
                    version_not_scanned_in_crxcavator[id]['name'],
                    id,
                    version,
                    version_not_scanned_in_crxcavator[id]['latest_version'],
                    "https://chrome.google.com/webstore/detail/{0}".format(id),
                    ';'.join(version_not_scanned_in_crxcavator[id][version]['devices']),
                    str(len(version_not_scanned_in_crxcavator[id][version]['devices'])),
                    ';'.join(version_not_scanned_in_crxcavator[id][version]['users']),
                    str(len(version_not_scanned_in_crxcavator[id][version]['users'])),
                    str(version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].risk_score),
                    json.dumps(version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].risk_csp, indent=2),
                    json.dumps(version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].risk_external_javascript, indent=2),
                    json.dumps(version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].risk_external_calls, indent=2),
                    json.dumps(dangerous_funcs, indent=2),
                    json.dumps(version_not_scanned_in_crxcavator[id]['risk_associated_with_latest_version'].entry_points, indent=2)
                ]
            char_length = 0
            if len(';'.join(version_not_scanned_in_crxcavator[id][version]['users'])) > 49000:
                char_length = len(';'.join(version_not_scanned_in_crxcavator[id][version]['users']))

            if len(';'.join(version_not_scanned_in_crxcavator[id][version]['devices'])) > 49000 and len(';'.join(version_not_scanned_in_crxcavator[id][version]['devices'])) > char_length:
                char_length = len(';'.join(version_not_scanned_in_crxcavator[id][version]['devices']))

            users_list = []
            device_list = []

            if len(';'.join(version_not_scanned_in_crxcavator[id][version]['users'])) > 49000:
                number_in_each_user_block_list = ceil(len(version_not_scanned_in_crxcavator[id][version]['users']) / ceil(char_length / 45000))
                users_list = [version_not_scanned_in_crxcavator[id][version]['users'][i:i + number_in_each_user_block_list] for i in range(0, len(version_not_scanned_in_crxcavator[id][version]['users']), number_in_each_user_block_list)]

            if len(';'.join(version_not_scanned_in_crxcavator[id][version]['devices'])) > 49000:
                number_in_each_device_block_list = ceil(len(version_not_scanned_in_crxcavator[id][version]['devices']) / ceil(char_length / 45000))
                device_list = [version_not_scanned_in_crxcavator[id][version]['devices'][i:i + number_in_each_device_block_list] for i in range(0, len(version_not_scanned_in_crxcavator[id][version]['devices']), number_in_each_device_block_list)]

            if users_list or device_list:
                if users_list:
                    for index, users in enumerate(users_list):
                        sheet_row[7] = ';'.join(users)
                        sheet_row[8] = str(len(users))
                        if device_list:
                            try:
                                sheet_row[5] = ';'.join(device_list[index])
                                sheet_row[6] = str(len(device_list[index]))
                            except IndexError:
                                sheet_row[6] = ''
                                sheet_row[5] = ''
                        extensions.append(sheet_row)
                elif device_list:
                    for index, devices in enumerate(device_list):
                        sheet_row[5] = ';'.join(devices)
                        sheet_row[6] = str(len(devices))
                        extensions.append(sheet_row)
            else:
                extensions.append(sheet_row)

    logger.info('Updating spreadsheet %s in %s drive with data for Version Unavailable in Crxcavator' % (filename, team_drive))
    sheet.append_sheet(filename, extensions, gsuite_service_account, file_id, sheet_id)


def create_report_unscanned_extensions(extension_ids, extension_names, filename, file_id, sheet_id):
    extensions = ['Name,ID'.split(',')]
    for extension_id in extension_ids:
        extensions.append(
            [
                extension_names[extension_id],
                extension_id
            ]
        )
    logger.info('Updating spreadsheet %s in %s drive with data for Unscanned in Crxcavator' % (filename, team_drive))
    sheet.append_sheet(filename, extensions, gsuite_service_account, file_id, sheet_id)


def combine_chrome_extensions(chrome_extensions_per_device_per_user, risky_objects, latest_version_extension, paid_extensions, not_in_store):
    no_results_for_extension_name_version = {}
    paid_extension_per_id = {}
    removed_from_chrome_store_per_id = {}

    for device_name in chrome_extensions_per_device_per_user:
        for user in chrome_extensions_per_device_per_user[device_name]:
            for id in chrome_extensions_per_device_per_user[device_name][user]:
                if id in risky_objects:
                    for version in chrome_extensions_per_device_per_user[device_name][user][id]['version']:
                        if version in risky_objects[id]:
                            if user not in risky_objects[id][version].users:
                                risky_objects[id][version].users.append(user)

                            if device_name not in risky_objects[id][version].devices:
                                risky_objects[id][version].devices.append(device_name)
                        else:
                            if id in no_results_for_extension_name_version:
                                if version in no_results_for_extension_name_version[id]:
                                    if user not in no_results_for_extension_name_version[id][version]['users']:
                                        no_results_for_extension_name_version[id][version]['users'].append(user)
                                    if device_name not in no_results_for_extension_name_version[id][version]['devices']:
                                        no_results_for_extension_name_version[id][version]['devices'].append(device_name)
                                else:
                                    no_results_for_extension_name_version[id][version] = {
                                        'users': [user],
                                        'devices': [device_name]
                                    }

                            else:
                                no_results_for_extension_name_version[id] = {
                                    'name': '',
                                    'latest_version': '',
                                    'risk_associated_with_latest_version': None,
                                    version: {
                                        'users': [user],
                                        'devices': [device_name]
                                    }
                                }

                                for ver in risky_objects[id]:
                                    no_results_for_extension_name_version[id]['name'] = risky_objects[id][ver].name
                                    break

                                if id in latest_version_extension:
                                    no_results_for_extension_name_version[id]['latest_version'] = latest_version_extension[id]

                                    if no_results_for_extension_name_version[id]['latest_version'] in risky_objects[id]:
                                        no_results_for_extension_name_version[id]['risk_associated_with_latest_version'] = risky_objects[id][latest_version_extension[id]]

                elif id in paid_extensions:
                    if id in paid_extension_per_id:
                        for version in chrome_extensions_per_device_per_user[device_name][user][id]['version']:
                            if version in paid_extension_per_id[id]:
                                if user not in paid_extension_per_id[id][version]['users']:
                                    paid_extension_per_id[id][version]['users'].append(user)
                                if device_name not in paid_extension_per_id[id][version]['devices']:
                                    paid_extension_per_id[id][version]['devices'].append(device_name)
                            else:
                                paid_extension_per_id[id][version] = {
                                    'users': [user],
                                    'devices': [device_name]
                                }

                    else:
                        paid_extension_per_id[id] = {
                            'name': chrome_extensions_per_device_per_user[device_name][user][id]['name']
                        }
                        for version in chrome_extensions_per_device_per_user[device_name][user][id]['version']:
                            paid_extension_per_id[id][version] = {
                                'users': [user],
                                'devices': [device_name]
                            }

                elif id in not_in_store:
                    if id in removed_from_chrome_store_per_id:
                        for version in chrome_extensions_per_device_per_user[device_name][user][id]['version']:
                            if version in removed_from_chrome_store_per_id[id]:
                                if user not in removed_from_chrome_store_per_id[id][version]['users']:
                                    removed_from_chrome_store_per_id[id][version]['users'].append(user)
                                if device_name not in removed_from_chrome_store_per_id[id][version]['devices']:
                                    removed_from_chrome_store_per_id[id][version]['devices'].append(device_name)
                            else:
                                removed_from_chrome_store_per_id[id][version] = {
                                    'users': [user],
                                    'devices': [device_name]
                                }

                    else:
                        removed_from_chrome_store_per_id[id] = {
                            'name': chrome_extensions_per_device_per_user[device_name][user][id]['name']
                        }
                        for version in chrome_extensions_per_device_per_user[device_name][user][id]['version']:
                            removed_from_chrome_store_per_id[id][version] = {
                                'users': [user],
                                'devices': [device_name]
                            }
    return risky_objects, no_results_for_extension_name_version, paid_extension_per_id, removed_from_chrome_store_per_id


@click.command()
@click.option("-d", "--duration",  default=4, nargs=1, type=int, required=False, help="Duration in days greater than 3, that you want to pull the extensions from tenable (All workstations are scanned once in 3 days) ")
def main(duration: int):
    # Extract chrome extensions from tenable scan
    chrome_extensions_per_device_per_user, extension_ids_per_version, extension_ids_per_name = tenable.get_chrome_extensions(duration)

    risky_objects = {}
    extensions_to_run_reports_on = {}
    paid_extensions = []
    not_in_store = []
    extensions_to_scan_again = []
    new_extensions_to_scan_again = []
    not_an_extension = []
    latest_version_extension = {}

    # Submit all extensions to crxcavator to reduce the number of extensions to actually get a report on and classify the result accordingly
    logger.info('Found %d extensions' % len(extension_ids_per_version))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        fs = [executor.submit(crxcavator.submit_extension, extension_id) for extension_id in extension_ids_per_version]
        for future in concurrent.futures.as_completed(fs):
            scan_result = future.result()
            if scan_result['extension'] and not scan_result['not_free'] and not scan_result['removed_from_store']:
                extensions_to_run_reports_on[scan_result['id']] = extension_ids_per_version[scan_result['id']]
                if scan_result['version']:
                    latest_version_extension[scan_result['id']] = scan_result['version']
            elif scan_result['not_free']:
                paid_extensions.append(scan_result['id'])
            elif scan_result['removed_from_store']:
                not_in_store.append(scan_result['id'])
            elif scan_result['run_again']:
                extensions_to_scan_again.append(scan_result['id'])
            elif not scan_result['extension']:
                not_an_extension.append(scan_result['id'])

    # Try to scan extensions again that errored when submitted to crxcavator
    if extensions_to_scan_again:
        logger.info('Scanning %d extensions again' % len(extensions_to_scan_again))
        seconds_to_sleep = 90
        logger.info('Sleeping %d seconds' % seconds_to_sleep)
        time.sleep(seconds_to_sleep)
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            fs = [executor.submit(crxcavator.submit_extension, extension_id) for extension_id in extensions_to_scan_again]
            for future in concurrent.futures.as_completed(fs):
                scan_result = future.result()
                if scan_result['extension'] and not scan_result['not_free'] and not scan_result['removed_from_store']:
                    extensions_to_run_reports_on[scan_result['id']] = extension_ids_per_version[scan_result['id']]
                    if scan_result['version']:
                        latest_version_extension[scan_result['id']] = scan_result['version']
                elif scan_result['not_free']:
                    paid_extensions.append(scan_result['id'])
                elif scan_result['removed_from_store']:
                    not_in_store.append(scan_result['id'])
                elif scan_result['run_again']:
                    new_extensions_to_scan_again.append(scan_result['id'])
                elif not scan_result['extension']:
                    not_an_extension.append(scan_result['id'])

    logger.info('Unable to retreive %d extensions from webstore' % len(new_extensions_to_scan_again))
    logger.info('Found %d free extensions, %d non-extensions, %d paid-extensions & %d extensions not in store' % (len(extensions_to_run_reports_on), len(not_an_extension), len(paid_extensions), len(not_in_store)))

    # Fetch reports on the extension for a particular version
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        fs = [executor.submit(crxcavator.fetch_risk_details, extension_id, extension_ids_per_version[extension_id]) for extension_id in extensions_to_run_reports_on]
        for future in concurrent.futures.as_completed(fs):
            riskobjs = future.result()
            if riskobjs:
                for riskobj in riskobjs:
                    risky_extension_obj = RiskyExtensions(riskobj.id, riskobj.version)
                    #risky_extension_obj.name = extension_ids_per_name[risky_extension_obj.id]
                    risky_extension_obj.name = riskobj.name
                    risky_extension_obj.risk_csp = riskobj.risk_csp
                    risky_extension_obj.risk_external_javascript = riskobj.risk_external_javascript
                    risky_extension_obj.risk_external_calls = riskobj.risk_external_calls
                    risky_extension_obj.risk_score = riskobj.risk_score
                    risky_extension_obj.entry_points = riskobj.entry_points
                    risky_extension_obj.dangerous_functions = riskobj.dangerous_functions
                    risky_extension_obj.chrome_link = riskobj.chrome_link
                    risky_extension_obj.crxcavator_link = riskobj.crxcavator_link

                    if riskobj.id in risky_objects:
                        #risky_objects[risky_extension_obj.name][risky_extension_obj.version] = risky_extension_obj
                        risky_objects[riskobj.id][risky_extension_obj.version] = risky_extension_obj
                    else:
                        #risky_objects[risky_extension_obj.name] = {
                        risky_objects[riskobj.id] = {
                            risky_extension_obj.version: risky_extension_obj
                        }

    logger.info('Reworking chrome extensions to combine devices and users of the same extension and same version')
    risky_objects, no_results_for_extension_name_version, paid_extension_per_id, removed_from_chrome_store_per_id = combine_chrome_extensions(chrome_extensions_per_device_per_user, risky_objects, latest_version_extension, paid_extensions, not_in_store)

    del chrome_extensions_per_device_per_user
    
    # GOOGLE DRIVE STORAGE OPTION
    # YOU CAN CHANGE THE BELOW PART TO DOWNLOAD TO THE LOCATION OF YOUR CHOICE

    drive.drive_access_tokens[gsuite_service_account] = {}
    access_token, expiry = drive.generate_drive_api_access_token(gsuite_service_account)
    if access_token is not None and expiry is not None:
        drive.drive_access_tokens[gsuite_service_account]['access_token'] = access_token
        drive.drive_access_tokens[gsuite_service_account]['expiry'] = expiry

    drive_id = drive.find_drive(team_drive, gsuite_service_account)

    sheet.sheet_access_tokens[gsuite_service_account] = {}
    access_token, expiry = sheet.generate_sheet_api_access_token(gsuite_service_account)
    if access_token is not None and expiry is not None:
        sheet.sheet_access_tokens[gsuite_service_account]['access_token'] = access_token
        sheet.sheet_access_tokens[gsuite_service_account]['expiry'] = expiry

    if drive_id:
        logger.info('Finding folder "Chrome Extension Scanner" in %s drive' % team_drive)
        folder_id = drive.find_item("Chrome Extension Scanner", gsuite_service_account, drive_id, 'folder')
        if not folder_id:
            logger.info('Creating folder Chrome Extension Scanner in %s drive' % team_drive)
            folder_id = drive.create_file("Chrome Extension Scanner", gsuite_service_account, drive_id, 'folder')

        file_name = 'Chrome_Extension_Scan_(Crxcavator)_%s' % datetime.now().isoformat()
        file_id = drive.create_file(file_name, gsuite_service_account, drive_id, 'sheet', folder_id)

        if file_id and risky_objects:
            page = sheet.new_sheet(file_name, file_id, gsuite_service_account, ['Risky Chrome Extensions'])
            if 'Risky Chrome Extensions' in page and page['Risky Chrome Extensions']:
                create_report_risky_extensions(risky_objects, file_name, file_id, page['Risky Chrome Extensions'])

        if file_id and paid_extension_per_id:
            page = sheet.new_sheet(file_name, file_id, gsuite_service_account, ['Unscanned Paid Chrome Extensions'])
            if 'Unscanned Paid Chrome Extensions' in page and page['Unscanned Paid Chrome Extensions']:
                create_report_unscanned_paid_extensions(paid_extension_per_id, file_name, file_id, page['Unscanned Paid Chrome Extensions'])

        if file_id and removed_from_chrome_store_per_id:
            page = sheet.new_sheet(file_name, file_id, gsuite_service_account, ['Chrome Extensions Removed from Store'])
            if 'Chrome Extensions Removed from Store' in page and page['Chrome Extensions Removed from Store']:
                create_report_removed_from_store(removed_from_chrome_store_per_id, file_name, file_id, page['Chrome Extensions Removed from Store'])

        if file_id and no_results_for_extension_name_version:
            page = sheet.new_sheet(file_name, file_id, gsuite_service_account, ['Version Unavailable in Crxcavator'])
            if 'Version Unavailable in Crxcavator' in page and page['Version Unavailable in Crxcavator']:
                create_report_no_version_extension(no_results_for_extension_name_version, file_name, file_id, page['Version Unavailable in Crxcavator'])

        if file_id and new_extensions_to_scan_again:
            page = sheet.new_sheet(file_name, file_id, gsuite_service_account, ['Unscanned in Crxcavator'])
            if 'Unscanned in Crxcavator' in page and page['Unscanned in Crxcavator']:
                create_report_unscanned_extensions(new_extensions_to_scan_again, extension_ids_per_name, file_name, file_id, page['Unscanned in Crxcavator'])


if __name__ == "__main__":
    main()
