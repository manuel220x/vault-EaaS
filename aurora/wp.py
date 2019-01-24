import operator
import json
import os
import io
import pandas
import base64
from io import StringIO


class WorkPaper:
    """
    This class will decrypt the CSV files and then generate workpapers
    """

    def __init__(self, in_vault_client, in_clientid, in_input_path, in_out_path, in_logger):
        self.vault_client = in_vault_client
        self.clientid = in_clientid
        self.logger = in_logger
        self.dataset = []
        if not os.path.exists(in_input_path):
            raise Exception("Input folder doesn't exist")
        if os.path.exists(in_out_path):
            raise Exception("Destination path exist, must be empty")
        else:
            os.makedirs(in_out_path)
        self.in_folder = os.path.normpath(in_input_path)
        self.out_folder = os.path.normpath(in_out_path)

    def load_full_data(self):
        for filename in os.listdir(self.in_folder):
            file = self.in_folder + '/' + filename
            if os.path.isfile(file) and not filename.startswith('.'):
                # print(file)
                data = self.decrypt(file)
                self.dataset.append(
                    (filename, pandas.read_csv(StringIO(data.decode()))))

    def generate_wp_file(self, wp_type):
        if wp_type == 'monthly':
            writer = pandas.ExcelWriter(self.out_folder + '/montly.xlsx')
            for data in self.dataset:
                wp_dataset_total = self.generate_monthly(data[1]).sum()
                wp_final = wp_dataset_total[["TAX", "AMMOUNT"]]
                wp_final.to_excel(writer, data[0])
            writer.save()
        elif wp_type == 'yearly':
            writer = pandas.ExcelWriter(self.out_folder + '/yearly.xlsx')
            for data in self.dataset:
                wp_dataset_total = self.generate_yearly(data[1]).sum()
                wp_final = wp_dataset_total[["TAX", "AMMOUNT"]]
                wp_final.to_excel(writer, data[0])
            writer.save()
        return True

    def generate_monthly(self, data):
        data['TS'] = pandas.to_datetime(data['TS'])
        return data.groupby(data.TS.dt.month.rename("Month"))

    def generate_yearly(self, data):
        data['TS'] = pandas.to_datetime(data['TS'])
        return data.groupby(data.TS.dt.year.rename("Year"))
    """
    def generate_wp_file(self):
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
    """

    def decrypt(self, encoded_filepath):
        self.logger.info('Decoding {}'.format(encoded_filepath))
        content = self.vault_client.decrypt(self.clientid, encoded_filepath)
        if content == "":
            raise Exception("Error Decrypting file:" +
                            self.vault_client.last_message)
        return base64.decodebytes(content.encode())
        """
        if self.vault_client.encrypt(self.config.client_id, encoded_data.decode(), dest_filename):
            print('File {} created succesfully'.format(dest_filename))
        else:
            raise Exception(
                "Error received from API: {}".format(self.vault_client.last_message))
        """

    def print_values(self):
        for variable, value in vars(self).items():
            print(variable + ' = ' + str(value))
