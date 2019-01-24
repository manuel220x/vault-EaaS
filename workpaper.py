#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

# Temp Stuff
import shutil

# Required Stuff
import warnings
import os
import logging
import argparse
import urllib3
from aurora.wp import WorkPaper
from aurora.misc import ConfigParser
from aurora.vault import VaultClient
from pprint import pprint

LOG_FORMAT = '%(asctime)-15s [%(levelname)s] [%(module)s.%(funcName)s] %(message)s'
LOG_FILE = '/tmp/vault/logs/workpaper.log'
LOG_LEVEL = logging.INFO

# Temp Stuff
warnings.simplefilter(action='ignore', category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

# Logging Configuration
logging.basicConfig(format=LOG_FORMAT, filename=LOG_FILE, level=LOG_LEVEL)
local_logger = logging.getLogger('workpaper')

local_logger.info("Starting...")

# Parsing of Arguments
parser = argparse.ArgumentParser(
    description="Tool to read encrypted files, parse them and create Excel files to be used as workpapers\
    to decrypt files, the tool will connect to vault using values taken from the OS environmental variables\
    VHOST, VTOKEN and VCACERT")
parser.add_argument(
    "clientid", help="Specify the clientid you will be generating WP for")
parser.add_argument(
    "input_folder", help="Specify the path where the files will be taken from")
parser.add_argument(
    "output_folder", help="Specify the path where the files will be written to")
args = parser.parse_args()

# Instantiate the super vault's client library
vault = VaultClient(os.environ.get('VURL'),
                    os.environ.get('VTOKEN'), local_logger, in_cacert=os.environ.get('VCACERT'))

# The Real Work Starts here
wp = WorkPaper(vault, args.clientid, args.input_folder,
               args.output_folder, local_logger)
wp.load_full_data()
if wp.generate_wp_file('monthly'):
    print("Monlthly Documents Generated Succesfully!")
if wp.generate_wp_file('yearly'):
    print("Yearly Documents Generated Succesfully!")


local_logger.info("Done")
