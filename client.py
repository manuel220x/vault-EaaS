#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

"""
client.py

Script to manage keys, its just a wrapper that provies an easy management for the encryption keys, it allows you to 
perform the common operations: Create and delete keys and polocies associated with the key, get info about them 
and rotate them.

Usage:
./client.py <clientid> [-d] [--keeppolicy] [--keeptoken] [-n | -l | -r]

clientid      The client identifier which will be used as the actual id for the key in vault, should be unique
-n, --new     Create a new policy, token and key which will be associated with the given clientid
-l, --lookup  Get info about client
-r, --rotate  Rotate the key for the specified client

-d, --delete  Delete Key, policy and token associated with the client.
--keeppolicy  Do NOT remove policy associated with this client
--keeptoken   Do NOT remove Token associated with this client


Example:

./client.py mcronalds
    This will create a key identified by name: mcrolands, a policy and also a token which will only be allowed 
    to encrypt/decrypt data using this new key.

"""
import warnings
import logging
import sys
import argparse
import urllib3
import os
from aurora.vault import VaultClient


LOG_FORMAT = '%(asctime)-15s [%(levelname)s] [%(module)s.%(funcName)s] %(message)s'
LOG_FILE = '/tmp/vault/logs/client_management.log'
LOG_LEVEL = logging.INFO

# Temp Stuff
warnings.simplefilter(action='ignore', category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

# Logging Configuration
logging.basicConfig(format=LOG_FORMAT, filename=LOG_FILE, level=LOG_LEVEL)
local_logger = logging.getLogger('client')

local_logger.info("Starting...")

# Parsing of Arguments
parser = argparse.ArgumentParser(
    description="Tool to manage client Keys within Vault")
parser.add_argument(
    "clientid", help="The client id to use")
group = parser.add_mutually_exclusive_group()
delete_group = parser.add_argument_group()
delete_group.add_argument(
    "-d", "--delete", help="Delete Key, policy and token associated with the client.", action="store_true")
delete_group.add_argument(
    "--keeppolicy", help="Do NOT remove policy associated with this client", action="store_true")
delete_group.add_argument(
    "--keeptoken", help="Do NOT remove Token associated with this client", action="store_true")
group.add_argument(
    "-n", "--new", help="Create a new client", action="store_true")
group.add_argument(
    "-l", "--lookup", help="Get info about client", action="store_true")
group.add_argument(
    "-r", "--rotate", help="Rotate Key", action="store_true")
args = parser.parse_args()

if args.delete and (args.new or args.lookup or args.rotate):
    print("-d/--delete cannot be used with -n/--new, -l/--lookup, -r/--rotate")
    parser.print_help()
    sys.exit(1)

# The Real Work
vault = VaultClient(os.environ.get('VURL'),
                    os.environ.get('VTOKEN'), local_logger, in_cacert=os.environ.get('VCACERT'))

result = True
if args.lookup:
    local_logger.info(
        'Getting Key details for client: {}'.format(args.clientid))
    if vault.read_key(args.clientid):
        print('Key:')
        print(vault.last_message)
        if vault.get_token_info(args.clientid):
            print('Token:')
            print(vault.last_message)
        else:
            print('Token not found for this client')
    else:
        print(vault.last_message)
        result = False
if args.rotate:
    local_logger.info('Rotating key for client: {}'.format(args.clientid))
    if vault.rotate_key(args.clientid):
        print('Key Rotated Succesfully!')
    else:
        print(vault.last_message)
        result = False
if args.new:
    local_logger.info('Creating Policy for client {}'.format(args.clientid))
    if vault.create_policy(args.clientid):
        print('Policy Created Succesfully!')
        local_logger.info(
            'Creating New Key for client: {}'.format(args.clientid))
        if vault.create_token(args.clientid):
            print('Token Info: {}'.format(vault.last_message))
        else:
            print('Error creating token')
        if vault.create_key(args.clientid):
            print('Key Created Succesfully!')
        else:
            print(vault.last_message)
            result = False
    else:
        print(vault.last_message)
        result = False

if args.delete:
    local_logger.info('Deleting Key for client: {}'.format(args.clientid))
    if vault.delete_key(args.clientid):
        print('Key Deleted Succesfully!')
    else:
        print(vault.last_message)
        result = False
    if not args.keeppolicy:
        if vault.delete_policy(args.clientid):
            print('Policy Deleted Succesfully!')
        else:
            print(vault.last_message)
            result = False
    if not args.keeptoken:
        if vault.delete_token(args.clientid):
            print('Token Deleted Succesfully!')
        else:
            print(vault.last_message)
            result = False


if not result:
    sys.exit(-1)

local_logger.info("Done")
