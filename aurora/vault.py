import requests
import json


class VaultClient:
    def __init__(self, in_url, in_token=None, in_logger=None, in_version='v1', in_cacert=None):
        self.url = in_url
        self.last_message = ''
        self.logger = in_logger
        self.version = in_version
        self.token = in_token
        self.headers = {'X-Vault-Token': self.token}
        self.cacert = in_cacert
        if self.verify_token() == False:
            raise Exception('Authentication Error')

    def api(self, endpoint, method='GET', payload=None):
        url = '{url}/{version}{endpoint}'.format(
            url=self.url, version=self.version, endpoint=endpoint)
        self.logger.info(
            'Calling URI: {}, METHOD: {}, payload: {}'.format(url, method, payload))
        if method == 'GET':
            r = requests.get(url, headers=self.headers, verify=self.cacert)
        elif method == 'LIST':
            r = requests.request(
                'LIST', url, headers=self.headers, verify=self.cacert)
        elif method == 'DELETE':
            r = requests.request(
                'DELETE', url, headers=self.headers, verify=self.cacert)
        elif method == 'POST':
            r = requests.post(url, headers=self.headers,
                              data=json.dumps(payload), verify=self.cacert)
        elif method == 'PUT':
            r = requests.request('PUT', url, headers=self.headers,
                                 data=json.dumps(payload), verify=self.cacert)
        self.logger.debug('Response Code: {}'.format(r.status_code))
        self.logger.debug('Response Payload: {}'.format(r.text))
        return r

    def get_token_info(self, keyname):
        r = self.api('/auth/token/accessors', 'LIST')
        if r.status_code == 200:
            accesor_list = r.json()['data']['keys']
            already_exist = False
            for accesor in accesor_list:
                r_accesor_query = self.api(
                    '/auth/token/lookup-accessor', 'POST', {"accessor": accesor})
                if r_accesor_query.status_code == 200:
                    if r_accesor_query.json()['data']['meta'] is not None:
                        if r_accesor_query.json()['data']['meta']['clientid'] == keyname:
                            already_exist = True
                            self.last_message = json.dumps(
                                r_accesor_query.json()['data'], indent=4, sort_keys=True)
            return already_exist
        else:
            self.logger.error(r.text)
            return False
        return True

    def verify_token(self):
        r = self.api('/auth/token/lookup-self')
        self.logger.debug(r.json())
        if r.status_code == 200:
            return True
        else:
            self.logger.error(r.json())
            return False

    def create_token(self, keyname):
        r = self.api('/auth/token/accessors', 'LIST')
        if r.status_code == 200:
            accesor_list = r.json()['data']['keys']
            already_exist = False
            for accesor in accesor_list:
                r_accesor_query = self.api(
                    '/auth/token/lookup-accessor', 'POST', {"accessor": accesor})
                if r_accesor_query.status_code == 200:
                    if r_accesor_query.json()['data']['meta'] is not None:
                        if r_accesor_query.json()['data']['meta']['clientid'] == keyname:
                            already_exist = True
            if not already_exist:
                payload = {"policies": ["policy-" + keyname],
                           "meta": {"clientid": keyname}}
                r_create = self.api('/auth/token/create', 'POST', payload)
                if r_create.status_code != 200:
                    self.logger.error(r_create.text)
                    self.last_message = 'Error: Not able to create Token'
                    return False
                else:
                    self.last_message = r_create.json(
                    )['auth']['client_token']
                    return True
            else:
                self.logger.error('Token for specified client already exist')
                self.last_message = 'Warning: Token for the specified client already exist'
                return True
        else:
            self.logger.error(r.text)
            return False
        return True

    def create_policy(self, keyname):
        r = self.api('/sys/policy', 'GET')
        if r.status_code == 200:
            keys = r.json()['data']['policies']
            if 'policy-' + keyname not in keys:
                self.logger.info('Creating Policy')
                policy_str = """path \"/transit/decrypt/{c}\" {{
                    capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]
                }}
                path \"/transit/encrypt/{c}\" {{
                    capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]
                }}

                path \"/transit/keys\" {{
                    capabilities = [\"list\"]
                }}
                """.format(c=keyname)
                payload = {"policy": policy_str}
                r_create = self.api('/sys/policy/policy-' +
                                    keyname, 'PUT', payload)
                if r_create.status_code != 204:
                    self.logger.error(r_create.text)
                    self.last_message = 'Error: Not able to create Key'
                    return False
            else:
                self.logger.error('Policy Already exist')
                self.last_message = 'Error: The specified policy already exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def read_key(self, keyname):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Searching Key')
                r_key = self.api('/transit/keys/' + keyname)
                if r_key.status_code == 200:
                    self.last_message = json.dumps(
                        r_key.json()['data'], indent=4, sort_keys=True)
                else:
                    self.logger.error(r_key.text)
                    self.last_message = 'Error: Key couldn not be retreived'
                    return False
            else:
                self.logger.error('Key doesn\'t exist')
                self.last_message = 'Error: The specified key does not exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def rotate_key(self, keyname):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Rotating Key')
                payload = {}
                r_rotate = self.api('/transit/keys/{}/rotate'.format(
                                    keyname), 'POST', payload)
                if r_rotate.status_code != 204:
                    self.logger.error(r_rotate.text)
                    self.last_message = 'Error: Not able to create Key'
                    return False
            else:
                self.logger.error('Key does not exist')
                self.last_message = 'Error: The specified key does not exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def create_key(self, keyname):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200 or r.status_code == 404:
            if r.status_code == 404:
                keys = ['None']
            else:
                keys = r.json()['data']['keys']
            if keyname not in keys:
                self.logger.info('Creating Key')
                payload = {"exportable": True,
                           "type": "aes256-gcm96"}
                r_create = self.api('/transit/keys/' +
                                    keyname, 'POST', payload)
                if r_create.status_code != 204:
                    self.logger.error(r_create.text)
                    self.last_message = 'Error: Not able to create Key'
                    return False
                else:
                    update_payload = {"deletion_allowed": True}
                    r_update = self.api('/transit/keys/{}/config'.format(
                                        keyname), 'POST', update_payload)
                    if r_update.status_code != 204:
                        self.logger.error(r_create.text)
                        self.last_message = 'Error: Not able to update deletion attribute of key'
                        return False
            else:
                self.logger.error('Key Already exist')
                self.last_message = 'Error: The specified key already exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def delete_token(self, keyname):
        r = self.api('/auth/token/accessors', 'LIST')
        if r.status_code == 200:
            accesor_list = r.json()['data']['keys']
            already_exist = False
            accessor_found = ""
            for accesor in accesor_list:
                r_accesor_query = self.api(
                    '/auth/token/lookup-accessor', 'POST', {"accessor": accesor})
                if r_accesor_query.status_code == 200:
                    if r_accesor_query.json()['data']['meta'] is not None:
                        if r_accesor_query.json()['data']['meta']['clientid'] == keyname:
                            already_exist = True
                            accessor_found = accesor
            if already_exist:
                payload = {"accessor": accessor_found}
                r_revoke = self.api(
                    '/auth/token/revoke-accessor', 'POST', payload)
                if r_revoke.status_code != 204:
                    self.logger.error(r_revoke.text)
                    self.last_message = 'Error: Not able to create Token'
                    return False
            else:
                self.logger.error('Token for specified client does not exist')
                self.last_message = 'Token for the specified client doesnt exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def delete_policy(self, keyname):
        r = self.api('/sys/policy', 'GET')
        if r.status_code == 200:
            policies = r.json()['data']['policies']
            if 'policy-' + keyname in policies:
                self.logger.info('Deleting Policy')
                r_rotate = self.api('/sys/policy/policy-{}'.format(
                                    keyname), 'DELETE')
                if r_rotate.status_code != 204:
                    self.logger.error(r_rotate.text)
                    self.last_message = 'Error: Not able to Delete Policy'
                    return False
            else:
                self.logger.error('Policy does not exist')
                self.last_message = 'The specified policy does not exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def delete_key(self, keyname):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Deleting Key')
                r_rotate = self.api('/transit/keys/{}'.format(
                                    keyname), 'DELETE')
                if r_rotate.status_code != 204:
                    self.logger.error(r_rotate.text)
                    self.last_message = 'Error: Not able to Delete Key'
                    return False
            else:
                self.logger.error('Key does not exist')
                self.last_message = 'Error: The specified key does not exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def decrypt_str(self, keyname, in_str):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Decrypting Data')
                r_decrypt = self.api('/transit/decrypt/{}'.format(keyname),
                                         'POST', {'ciphertext': in_str})
                if r_decrypt.status_code != 200:
                    self.logger.error(r_decrypt.text)
                    self.last_message = 'Error: Decryption failed'
                    return ""
                else:
                    self.logger.info(
                        'Response Received Succesfully')
                    return r_decrypt.json()['data']['plaintext']
            else:
                self.logger.error('Key does not exist')
                self.last_message = 'Error: The specified key does not exist'
                return ""
        else:
            self.logger.error(r.text)
            return ""
        return ""
    
    def decrypt(self, keyname, source_filename):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Decrypting Data')
                with open(source_filename, 'r') as input_file:
                    r_decrypt = self.api('/transit/decrypt/{}'.format(keyname),
                                         'POST', json.loads(input_file.read()))
                if r_decrypt.status_code != 200:
                    self.logger.error(r_decrypt.text)
                    self.last_message = 'Error: Decryption failed'
                    return ""
                else:
                    self.logger.info(
                        'Response Received Succesfully')
                    return r_decrypt.json()['data']
                    #return r_decrypt.json()['data']['plaintext']
            else:
                self.logger.error('Key does not exist')
                self.last_message = 'Error: The specified key does not exist'
                return ""
        else:
            self.logger.error(r.text)
            return ""
        return ""

    def encrypt_str(self, keyname, encoded_data):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Encrypting Data')
                r_encrypt = self.api('/transit/encrypt/{}'.format(keyname),
                                     'POST', {'plaintext': encoded_data})
                if r_encrypt.status_code != 200:
                    self.logger.error(r_encrypt.text)
                    self.last_message = 'Error: Encryption failed'
                    return False
                else:
                    self.logger.info(
                        'Response Received')
                    return r_encrypt.json()['data']
                    # print(r_encrypt.json()['data'])
            else:
                self.logger.error('Key does not exist')
                self.last_message = 'Error: The specified key does not exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True

    def get_datakey(self, keyname):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Encrypting Data')
                r_encrypt = self.api('/transit/datakey/plaintext/{}'.format(keyname),
                                     'POST', {})
                if r_encrypt.status_code != 200:
                    self.logger.error(r_encrypt.text)
                    self.last_message = 'Error: Not able to generate Key'
                    return False
                else:
                    self.logger.info(
                        'Response Received')
                    return r_encrypt.json()['data']
                    # print(r_encrypt.json()['data'])
            else:
                self.logger.error('Key does not exist')
                self.last_message = 'Error: The specified key does not exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True
    
    def encrypt(self, keyname, encoded_data, dest_filename):
        r = self.api('/transit/keys', 'LIST')
        if r.status_code == 200:
            keys = r.json()['data']['keys']
            if keyname in keys:
                self.logger.info('Encrypting Data')
                r_encrypt = self.api('/transit/encrypt/{}'.format(keyname),
                                     'POST', {'plaintext': encoded_data})
                if r_encrypt.status_code != 200:
                    self.logger.error(r_encrypt.text)
                    self.last_message = 'Error: Encryption failed'
                    return False
                else:
                    self.logger.info(
                        'Response Received, writing into filesystem')
                    with open(dest_filename, 'w') as encrypted_file:
                        json.dump(r_encrypt.json()['data'], encrypted_file)
                    # print(r_encrypt.json()['data'])
            else:
                self.logger.error('Key does not exist')
                self.last_message = 'Error: The specified key does not exist'
                return False
        else:
            self.logger.error(r.text)
            return False
        return True
