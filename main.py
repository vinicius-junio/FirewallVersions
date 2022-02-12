import abc
import urllib3
import requests
import logging
import xml.etree.ElementTree as ET
import os
import sqlite3
import xlsxwriter


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

list_tag = ['hostname', 'ip-address', 'public-ip-address', 'netmask', 'default-gateway', 'is-dhcp', 'ipv6-address',
            'ipv6-link-local-address', 'ipv6-default-gateway', 'mac-address', 'time', 'uptime', 'devicename', 'family', 'model',
            'serial', 'cloud-mode', 'sw-version', 'global-protect-client-package-version', 'app-version', 'app-release-date',
            'av-version', 'av-release-date', 'threat-version', 'threat-release-date', 'wf-private-version', 'wf-private-release-date',
            'url-db', 'wildfire-version', 'wildfire-release-date', 'url-filtering-version', 'global-protect-datafile-version',
            'global-protect-datafile-release-date', 'global-protect-clientless-vpn-version', 'global-protect-clientless-vpn-release-date',
            'logdb-version', 'platform-family', 'vpn-disable-mode', 'multi-vsys', 'operational-mode', 'device-certificate-status']

license_header = ['feature', 'description',
                  'issued', 'expires', 'expired', 'custom']
list_license = []

feature_list = ["PAN-DB URL Filtering", "Logging Service", "Threat Prevention","Premium","WildFire License"]

for n in range(0, len(feature_list)):
    for z in range(0, len(license_header)):
        list_license.append("%s-%i" % (license_header[z], n))

list_full = []
list_full.extend(list_tag)
list_full.extend(list_license)

class Storage:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def create_table(self, keys: list[str]) -> None:
        return

    @abc.abstractmethod
    def insert_information(self, value: list[str]) -> None:
        return

    @abc.abstractmethod
    def close(self) -> None:
        return


class SQLiteStorage(Storage):
    #
    # Storage data
    #
    def __init__(self, path) -> None:
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()

    def create_table(self, keys: list[str]):
        fields = '"' + '" TEXT, "'.join(keys) + '" TEXT'
        table = "CREATE TABLE IF NOT EXISTS \"Firewall\" (%s);" % (fields)

        self.cur.execute(table)
        self.con.commit()

    def insert_information(self, value: list[str]):
        self.cur.execute('INSERT INTO "Firewall" VALUES (%s)' %
                         (",".join(value)))
        self.con.commit()

    def close(self) -> None:
        self.con.close()


class XLSXStorage(Storage):
    #
    # Storage data in XLSX
    #
    def __init__(self, path) -> None:
        self.row = 0
        self.workbook = xlsxwriter.Workbook(path)
        self.worksheet = self.workbook.add_worksheet("Firewall")
        
    def create_table(self, keys: list[str]):
        for i in range(0, len(keys)):
            self.worksheet.write(self.row, i, keys[i])
        self.row += 1

    def insert_information(self, value: list[str]):

        for i in range(0, len(value)):
            information = value[i]
            if information.startswith('"') and information.endswith('"'):
                information = information[1:-1]
            if information == "NULL":
                continue
            self.worksheet.write(self.row, i, information)
        self.row += 1

    def insert_format(self):
        header_full = []
        for j in list_full:
            header_full.append({'header':j})
        self.worksheet.add_table(0,0,self.row - 1,len(header_full) -1,{'name':'Firewall','columns':header_full}) 

    def close(self) -> None:
        self.workbook.close()


class Discover:
    #
    # Search IP (Firewalls)
    #
    def __init__(self, file: str) -> None:
        with open(file, 'r') as f:
            self.urls = f.read().splitlines()


class Webservice:
    #
    # Connect with API Servers
    #
    def __init__(self, keys: list[str], licensesColum: list[str], user: str, password: str) -> None:
        self.keys = keys
        self.licensesColum = licensesColum
        self.credential = {
            'type': 'keygen',
            'user': user,
            'password': password,
        }

    def get_credential(self, url: str) -> str:
        service = "{}/api/".format(url)
        response = requests.post(service, params=self.credential, verify=False)

        status_code = response.status_code
        if status_code != 200:
            raise Exception("StatusCode {} != 200".format(status_code))

        return ET.fromstring(response.text).findall('result')[0].find('key').text

    def get_firewall_info(self, url: str, credential: str) -> list[str]:
        url = "{}/api/?key={}&type=op&cmd=<show><system><info></info></system></show>".format(url,credential)
        response = requests.post(url, verify=False)

        status_code = response.status_code
        if status_code != 200:
            raise Exception("StatusCode {} != 200".format(status_code))

        items = []
        root = ET.fromstring(response.text)
        result = root.findall('result')[0][0]

        for i in range(0, len(self.keys)):
            return_data = result.find(self.keys[i]).text
            if (type(return_data) == str):
                items.append('"{}"'.format(return_data))
            else:
                items.append("NULL")

        return items

    def get_firewall_info_license(self, url: str, credential: str) -> list[str]:
        url = "{}/api/?key={}&type=op&cmd=<request><license><info></info></license></request>".format(
            url, credential)
        response = requests.post(url, verify=False)

        status_code = response.status_code
        if status_code != 200:
            raise Exception("StatusCode {} != 200".format(status_code))

        items_license = []
        root = ET.fromstring(response.text)
        entries = root.findall('result')[0][0].findall('entry')

        data = {}
        for indexEntry in range(0, len(entries)):
            temp = []
            key = ""
            for indexColumn in range(0, len(license_header)):
                item = entries[indexEntry].find(license_header[indexColumn])
                if item != None:
                    item = item.text
                if type(item) == str:
                    if indexColumn == 0:
                        key = item.strip()
                    temp.append('"{}"'.format(item.strip()))
                else:
                    temp.append("NULL")
            data[key] = temp

        items_license = []
        for indexEntry in range(0, len(feature_list)):
            if feature_list[indexEntry] in data:
                items_license.extend(data[feature_list[indexEntry]])
            else:
                for z in range(0, len(license_header)):
                    items_license.append("NULL")
        return items_license


def main():
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.INFO,
        filename='error_firewall.log',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    directory = os.path.dirname(__file__)
    file = os.path.join(directory, "ips", "ip_list.txt")

    discover = Discover(file)

    sqlite_storage: Storage = SQLiteStorage("firewall.db")
    xlsx_storage: Storage = XLSXStorage("firewall.xlsx")

    sqlite_storage.create_table(list_full)
    xlsx_storage.create_table(list_full)

    connector = Webservice(list_tag, list_license, 'user', 'password')

    for url in discover.urls:
        try:
            credential = connector.get_credential(url)
            values = connector.get_firewall_info(url, credential)
            
            licenseArray = connector.get_firewall_info_license(url, credential)
            values.extend(licenseArray)

            sqlite_storage.insert_information(values)
            xlsx_storage.insert_information(values)

        except Exception as e:
            logging.warning("Falha na url: {}".format(url))

    xlsx_storage.insert_format()
    sqlite_storage.close()
    xlsx_storage.close()


if __name__ == "__main__":
    main()
