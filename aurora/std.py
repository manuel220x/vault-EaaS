import operator
import json
import os
import io
import pandas
import base64
from io import StringIO


class Standarization:
    """
    The class will be used to perform the transformations required into the files,
    it will use the configuration specific for the client and then it will create
    the CSV files accordingly and finally encrypt the data using Vault's transit engine
    """

    def __init__(self, in_vault_client, in_file, in_config, in_out_path, in_logger):
        self.vault_client = in_vault_client
        self.CONDITIONS = {"==": operator.eq, "!=": operator.ne}
        self.config = in_config
        self.logger = in_logger
        if not os.path.isfile(in_file):
            raise Exception("File doesn't exist")
        if os.path.exists(in_out_path):
            raise Exception("Destination path exist, must be empty")
        else:
            os.makedirs(in_out_path)
        self.file = in_file
        self.out_folder = os.path.normpath(in_out_path)

    def load_full_data(self):
        csv_encoded = self.vault_client.decrypt(
            self.config.client_id, self.file)
        if csv_encoded == "":
            raise Exception("Error Decrypting file:" +
                            self.vault_client.last_message)
        csv_content = base64.decodebytes(csv_encoded.encode())
        if not self.config.headers:
            self.data = pandas.read_csv(
                StringIO(csv_content.decode()), header=None)
        else:
            self.data = pandas.read_csv(StringIO(csv_content.decode()))
        self._rename_columns()

    def _rename_columns(self):
        for column in list(self.data):
            for new_name, column_names in self.config.rename_dict.items():
                if column in column_names:
                    self.data.rename(columns={column: new_name}, inplace=True)

    def generate_std_file(self):
        self.logger.info('Evaluating {} condition(s)'.format(
            self.config.total_conditions))
        for condition in self.config.conditions:
            self.logger.info('Field: {}, Value: {}'.format(
                condition['field'], condition['value']))
            require_rename = False
            fields_to_extract = []
            rename_dict = {}
            for item in condition['mapping']:
                if isinstance(item, (list,)):
                    require_rename = True
                    fields_to_extract.append(item[0])
                    rename_dict[item[0]] = item[1]
                else:
                    fields_to_extract.append(item)

            self.logger.info('Fields to extract: {}'.format(fields_to_extract))
            new_data_frame = self.data.loc[
                self.CONDITIONS[condition['conditional']](self.data[condition['field']], condition['value']), fields_to_extract]
            if require_rename:
                new_data_frame.rename(columns=rename_dict, inplace=True)

            dest_filename = self.out_folder + '/' + os.path.splitext(os.path.basename(self.file))[
                0] + '_' + condition['id'] + os.path.splitext(os.path.basename(self.file))[1]
            self.logger.info('Writing to {}'.format(dest_filename))
            csv_string = new_data_frame.to_csv(index=False)
            csv_encoded = base64.encodebytes(csv_string.encode())
            self.encrypt(csv_encoded, dest_filename)

    def encrypt(self, encoded_data, dest_filename):
        self.logger.info(encoded_data)

        if self.vault_client.encrypt(self.config.client_id, encoded_data.decode(), dest_filename):
            print('File {} created succesfully'.format(dest_filename))
        else:
            raise Exception(
                "Error received from API: {}".format(self.vault_client.last_message))

    def print_values(self):
        for variable, value in vars(self).items():
            print(variable + ' = ' + str(value))
