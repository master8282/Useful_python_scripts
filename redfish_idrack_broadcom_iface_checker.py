#!/usr/bin/python3

import argparse
import getpass
import logging
import requests
import sys
import warnings

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description=("Python script using Redfish \
API DMTF to either get or set OEM network device properties. \
This will configure properties which are not exposed as being supported \
from DMTF. Examples: virtual MAC address or virtualization mode."))
parser.add_argument('-ip', help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument(
    '-p',
    help=("iDRAC password. If you do not pass in argument -p, script will \
prompt to enter user password which will not be echoed to \
the screen."),
    required=False)
parser.add_argument(
    "-c",
    help=("path to yaml file with ips, for example './aic-clcp-site-manifests\
/site/mtn65c/baremetal/nodes.yaml'"),
    required=False)
parser.add_argument(
    '-x',
    help=("Pass in X-Auth session token for executing Redfish calls. \
All Redfish calls will use X-Auth token instead of \
username/password"),
    required=False)
parser.add_argument(
    '--ssl',
    help=("SSL cert verification for all Redfish calls, pass in value\
\'true\' or \'false\'. By default, this argument is not required and \
script ignores validating SSL cert for all \
Redfish calls."),
    required=False)
parser.add_argument(
    '--all',
    help="Show info about all interfaces as table. Default interface id is \
'NIC.Integrated.1-1-1'", action="store_true", dest="scan_all", required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout,
                    level=logging.INFO)


def get_network_device_fqdds(idrac_ip):
    ids = list()
    if args["x"]:
        response = requests.get(
            (f"https://{idrac_ip}/redfish/v1/Systems/System.Embedded.1/\
NetworkAdapters"),
            verify=verify_cert,
            headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get(
            (f"https://{idrac_ip}/redfish/v1/Systems/System.Embedded.1/\
NetworkAdapters"),
            verify=verify_cert,
            auth=(idrac_username, idrac_password))
    data = response.json()
    network_device_list = []
    for i in data['Members']:
        for ii in i.items():
            network_device = ii[1].split("/")[-1]
            network_device_list.append(network_device)

    for i in network_device_list:
        if args["x"]:
            response = requests.get(
                (f"https://{idrac_ip}/redfish/v1/Systems/System.Embedded.1/\
NetworkAdapters/{i}/NetworkDeviceFunctions"),
                verify=verify_cert,
                headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get(
                (f"https://{idrac_ip}/redfish/v1/Systems/System.Embedded.1/\
NetworkAdapters/{i}/NetworkDeviceFunctions"),
                verify=verify_cert,
                auth=(idrac_username, idrac_password))
        data = response.json()

        values = list(data['Members'][0].values())
        if values:
            ids.append(values[0].split("/")[-1])
    return ids


def get_network_device_attributes(network_id, idrac_ip):
    netcut_id = network_id.split("-")[0]
    if args["x"]:
        response = requests.get(
            (f"https://{idrac_ip}/redfish/v1/Chassis/System.Embedded.1/\
NetworkAdapters/{netcut_id}/NetworkDeviceFunctions/\
{network_id}/Oem/Dell/DellNetworkAttributes/{network_id}"),
            verify=verify_cert,
            headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get(
            (f"https://{idrac_ip}/redfish/v1/Chassis/System.Embedded.1/\
NetworkAdapters/{netcut_id}/NetworkDeviceFunctions/\
{network_id}/Oem/Dell/DellNetworkAttributes/{network_id}"),
            verify=verify_cert,
            auth=(idrac_username, idrac_password))
    data = response.json()
    return [netcut_id,
            data['Attributes']['ChipMdl'],
            data['Attributes']['MacAddr']]


def read_conf(path, ip_file_parse_filter):

    import re
    with open(path, "r") as conf_file:
        text = conf_file.read()
        text = re.findall(rf"{ip_file_parse_filter}", text)
    return [i[1] for i in text]


if __name__ == "__main__":
    fast_scan_net_id = 'NIC.Integrated.1-1-1'
    bcm_filter = 'BCM'
    bcm_mac_lst = ['90:8D:6E', 'F0:D4:E2']
    ip_file_parse_filter = (
        "(-\snetwork\W*oob\W*address\W*)(\d*.\d*.\d*.\d*)(\W*)")
    bcm_detect = False

    if (args["ip"] or args["c"] or args["ssl"] or args["u"] or
            args["p"] or args["x"]):
        if args["ip"]:
            idrac_ips = [(args["ip"])]
        elif args["c"]:
            idrac_ips = read_conf(args["c"], ip_file_parse_filter)
        else:
            logging.error(
                    ("\n- FAIL, you need '-ip' or '-c' parameters passed in. \
See help text or argument --script-examples for more details."))
            sys.exit(0)
        idrac_username = args["u"]
        if args["p"]:
            idrac_password = args["p"]
        if not args["p"] and not args["x"] and args["u"]:
            idrac_password = getpass.getpass(
                (f"\n- Argument -p not detected, pass in iDRAC user \
{args['u']} password: "))
        if args["ssl"]:
            if args["ssl"].lower() == "true":
                verify_cert = True
            elif args["ssl"].lower() == "false":
                verify_cert = False
            else:
                verify_cert = False
        else:
            verify_cert = False
    else:
        logging.error(
            ("\n- FAIL, invalid argument values or not all required \
parameters passed in. See help text or argument \
--script-examples for more details."))
        sys.exit(0)

    for idrac_ip in idrac_ips:
        if not args["scan_all"]:
            network_ids = [fast_scan_net_id]
        else:
            from prettytable import PrettyTable
            out_table = PrettyTable()
            out_table.field_names = ['Name', 'Model', 'MAC']
            network_ids = get_network_device_fqdds(idrac_ip)

        for network_id in network_ids:
            try:
                name, model, mac = get_network_device_attributes(
                    network_id, idrac_ip)
                if bcm_filter in model or mac[:8] in bcm_mac_lst:
                    bcm_detect = True
                if args["scan_all"]:
                    out_table.add_row([name, model, mac])
            except Exception:
                print(f"Coulldn't get info about the interface {network_id}.")

        if args["scan_all"]:
            out_table.align = "l"
            print(out_table)

        if bcm_detect:
            print(f"{idrac_ip} looks like 'Broadcom' net card has been found!")
        else:
            print(f"{idrac_ip} looks good")
