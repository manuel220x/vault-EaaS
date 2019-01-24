import os
import json


class ConfigParser:
    def __init__(self, in_file, in_logger):
        self.logger = in_logger
        if not os.path.isfile(in_file):
            raise Exception("File doesn't exist")
        else:
            self.filepath = in_file
        with open(self.filepath) as f:
            data = json.load(f)
        self._set_variables(data)
        # pprint (data)

    def _set_variables(self, in_data):
        self.client_id = in_data["client_id"]
        self.headers = in_data["headers"]
        self.rename_dict = in_data["rename_headers"]
        self.total_conditions = len(in_data["index_mapping"]["conditions"])
        self.conditions = in_data["index_mapping"]["conditions"]
        self.default_mapping = in_data["index_mapping"]["default"]

    def print_values(self):
        for variable, value in vars(self).items():
            print(variable + ' = ' + str(value))
