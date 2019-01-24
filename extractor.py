#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

"""
extractor.py

This script will simulate the actual process of extraction with the function query_erp, so currently the function only 
reads data from a plain text file, in the real scenario, this function performs an actual query to the ERP system. After
the information is retreived, it will be encrypted by the main VaultClient class and the resulting encrypted file and its
metadata will be written to the specified path.

Usage:
./extractor.py <clientid> <destination_file>

clientid      The client identifier
destination_file  A file where to write the data


Example:

./extractor.py mcronalds /tmp/encrypted.vault
    A file will be created under the specified path, with the encrypted CSV file and some metadata.

"""

# Required Stuff
import warnings
import logging
import argparse
import urllib3
import base64
import os
from aurora.vault import VaultClient

# We will simulate the actuall call to the ERP system, by just reading the content of a CSV file
DUMMY_FILE = '/tmp/vault/mike.csv'


def query_erp():
    with open(DUMMY_FILE, 'r') as dummy_file:
        csv_content = dummy_file.read()
    return csv_content


LOG_FORMAT = '%(asctime)-15s [%(levelname)s] [%(module)s.%(funcName)s] %(message)s'
LOG_FILE = '/tmp/vault/logs/extractor.log'
LOG_LEVEL = logging.DEBUG

# Temp Stuff
warnings.simplefilter(action='ignore', category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

# Logging Configuration
logging.basicConfig(format=LOG_FORMAT, filename=LOG_FILE, level=LOG_LEVEL)
local_logger = logging.getLogger('extactor')

local_logger.info("Starting...")

# Parsing of Arguments
parser = argparse.ArgumentParser(
    description="Tool that simulates extraction of ERP systems")
parser.add_argument(
    "clientid", help="The client id to use")
parser.add_argument(
    "destination_file", help="A file where to write the data")

args = parser.parse_args()

# The Real Work
vault = VaultClient(os.environ.get('VURL'),
                    os.environ.get('VTOKEN'), local_logger, in_cacert=os.environ.get('VCACERT'))

csv_data = query_erp()

if vault.encrypt(args.clientid, base64.encodebytes(
        csv_data.encode()).decode(), args.destination_file):
    print("Data extracted and encoded succesfully!")

local_logger.info("Done")
