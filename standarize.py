#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

"""
standarize.py

Tool that would take csv file and its configuration to then parse the file,
transform the data based on the given configuration and then create files ready 
to be used to create tax workpapers, every output file will be encrypted calling 
Vault API, the connection details to vault are taken from environmen variables: 
VURL, VTOKEN and VCACERT

Usage:
./standarize.py <encrypted_file> <config_file> <output_folder>

  encrypted_file  Specify the path of the file you want to parse
  config_file     Specify the path of the configuration file that has the mapping for the standarization
  output_folder   Specify the path where the files will be written


Example:

./standarize.py /tmp/vault/files/mcronalds_encrypted.vault /tmp/vault/config/mcronalds.json /tmp/vault/output/mcronalds
    
    The encrypted CSV file will be read from mcronalds_encrypted.vault and then using the mapping and client data taken from
    the mcronalds.json file, the script will multiple files (based on the content of the json file) and put them encrypted
     under the /tmp/vault/output/mcronalds directory.

"""

# Temp Stuff
#import shutil

# Required Stuff
import warnings
import os
import logging
import urllib3
import argparse
from aurora.std import Standarization
from aurora.misc import ConfigParser
from aurora.vault import VaultClient

LOG_FORMAT = '%(asctime)-15s [%(levelname)s] [%(module)s.%(funcName)s] %(message)s'
LOG_FILE = '/tmp/vault/logs/standarizaton.log'
LOG_LEVEL = logging.DEBUG

# Temp Stuff
warnings.simplefilter(action='ignore', category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
# shutil.rmtree('/tmp/vault/output/sample')

# Logging Configuration
logging.basicConfig(format=LOG_FORMAT, filename=LOG_FILE, level=LOG_LEVEL)
local_logger = logging.getLogger('standarization')

local_logger.info("Starting...")

# Parsing of Arguments
parser = argparse.ArgumentParser(
    description="Tool that would take csv file and configuration to parse, \
    transform data and then create files ready to be used to create workpapers, \
    every output file will be encrypted calling Vault API, the connection details\
    to vault are taken from env variables: VURL, VTOKEN and VCACERT")
parser.add_argument(
    "encrypted_file", help="Specify the path of the file you want to parse")
parser.add_argument(
    "config_file", help="Specify the path of the configuration file to use for parsing")
parser.add_argument(
    "output_folder", help="Specify the path where the files will be written")
args = parser.parse_args()

# Instantiate configuration Class
config = ConfigParser(args.config_file, local_logger)

# Instantiate vault using credentials
vault = VaultClient(os.environ.get('VURL'),
                    os.environ.get('VTOKEN'), local_logger, in_cacert=os.environ.get('VCACERT'))

# The Real Work
std = Standarization(vault, args.encrypted_file, config,
                     args.output_folder, local_logger)
std.load_full_data()
std.generate_std_file()


local_logger.info("Done")
