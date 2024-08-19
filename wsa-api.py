#!\usr\bin\python3
"""
Script uses Cisco Web Security Appliance API to connect to Cisco WSA devices, gets some info and saves the output to a file.

Usage: wsa-api.py [[-i] <device_ip> | [-j] <json_list_of_devices>] [-c] <command>  [OPTIONs]
COMMANDS:
-h --help Help screen
-d --debug Additional debug info
-i --ip single host IP address
-j --json json formated file with list of WSA devices and respected commands (mandatory)
-c --command single command to execute (mandatory)
"""
# Module import
import sys
import time
import getopt
#import os
#import subprocess
from getpass import getpass
import json
import base64
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError
from http import HTTPStatus

# Disable SSL warnings. Not needed in production environments with valid certificates
import urllib3
urllib3.disable_warnings()

# loading logging and preparing to log
import logging

# GLOBALS
HELP = "Script uses Cisco Web Security Appliance API to connect to Cisco WSA devices,\r\n \
gets some info and saves the output u a file\r\n\r\n \
Usage: wsa-api.py [[-i] <device_ip> | [-j] <json_list_of_devices>] [-c] <command>  [OPTIONs]\r\n\r\n \
COMMANDS:\r\n \
-h --help Help screen\r\n \
-d --debug Additional debug info\r\n \
-i --ip single host IP address\r\n \
-j --json json formated file with list of WSA devices and respected commands (mandatory)\r\n \
-c --command single command to execute (mandatory)\r\n\r\n"

# Base & Authentication info
#BASE_URL = 'http://172.30.92.11'
#BASE_SECURE_URL = 'https://172.30.92.11'
BASE_PORT = ':6080'
BASE_SECURE_PORT = ':6443'

# URIs
AUTH_URI = '/wsa/api/v2.0/login' # autentikacija
# CMD URIs
SL_URI = '/wsa/api/v3.0/system_admin/smart_software_licensing_status'
cmd_list = {"license": SL_URI}

# program exit function (with error message)
def exit_error(err_message="Unknown error"):
    """
    Exit function expanded with detail error message. Program exits to shellwith error code.

    Input: Error message
    """
    print(err_message)
    print(HELP)
    sys.exit(2)

# error message function
def continue_error(err_message="Unknown error"):
    """
    Error function with detail error message. Continues code execution.

    Input: Error message
    """
    print (err_message)
    print ("Continuing with execution!")
    return

def print_response(response):
  """
  Function used in debug to rpint complete HTTP response from the Cisco WSA device.
  """
  print ("Cijeli odgovor{}".format("\n"),response.status_code,"{}".format("\n"), response.headers, "{}".format("\n"), response.json())

def generate_auth_data():
  """
  Function that prepares authentication data. Converts Cisco WSA username and password into base64 encoded strings used for getting authentication token form WSA.
  """
  
  # pretvaranje wsa username i password-a u base64 enkodirane stringove unutar json payloada
  auth_details = {}
  auth_details["data"] = {}
  #username_bytes = USERNAME.encode("ascii")
  username_bytes = sys_params["wsa_user"].encode("ascii")
  username_b64_bytes = base64.b64encode(username_bytes)
  auth_details["data"]["userName"] = username_b64_bytes.decode("ascii")
  #password_bytes = PASSWORD.encode("ascii")
  password_bytes = sys_params["wsa_pass"].encode("ascii")
  password_b64_bytes = base64.b64encode(password_bytes)
  auth_details["data"]["passphrase"] = password_b64_bytes.decode("ascii")
  return json.dumps(auth_details)

# populating device list and options
def prepare_device_data(cmd_options):
    """
    Function does formating of input data, such as device list and device command list files, commands and options
    The output is populated dictionary with devices parameters and device commands
    """

    default_TYPE = "cisco_wsa"
    default_MODEL = "S300v" 
    default_CMD = "license"
    default_LIST = "yes"
    default_DEBUG = False  #indicating that invoke should provide additional debug info about various variable values
    cmd_list = ["license"]
    
    global sys_params
    global device_list
    sys_params = {"filename":"wsa-devices", "time_start":time.asctime(), "device_type": default_TYPE, "datamodel":default_MODEL, \
                "debug": default_DEBUG, "command": default_CMD, "listed": default_LIST, "wsa_user": "", "wsa_pass": ""}
    device_list = {}
    mandatory_options=0
    # analysis and prepraration of input arguments
    for curr_opts, curr_vals in cmd_options:
        if curr_opts in ("-h", "--help"):
            print(HELP)
            sys.exit(0)
        elif curr_opts in ("-d","--debug"):
            sys_params["debug"] = True
        elif curr_opts in ("-i","--ip"):
          mandatory_options+=1
          temp_hostname="vcfwsa"+curr_vals.split(".")[3]
          device_list[curr_vals]={"device_type": sys_params["device_type"], "hostname": temp_hostname, "listed": sys_params["listed"]}
        elif curr_opts in ("-j","--json"):
            mandatory_options+=1
            sys_params["datamodel"]="json"
            sys_params["host_file_name"]=curr_vals
            try:
                hostfile=open(sys_params['host_file_name'],'r')
                # OPEN JSON FILE AND DO SOMETHING
                device_list=json.load(hostfile)
                if (sys_params["debug"]):
                  print("\nLoaded JSON data (def(prepare_device_data))")
                  print (device_list)    
            except FileNotFoundError as err:
                exit_error(err)
        elif curr_opts in ("-c","--command"):
            mandatory_options+=1
            sys_params["command"]=curr_vals
            if sys_params["command"].lower() not in cmd_list:
               exit_error("Feature not yet implemented!")
        else:
            exit_error("Undefined input options error")
    if mandatory_options != 2:
       exit_error("Mandatory options are missing or there are too many of mandatory options!")
    # provjera analize input argumenata
    if (sys_params["debug"]):
        print("\nPripremljeni device i system podaci (def(prepare_device_data))")
        print (sys_params)
        print (device_list)
    # Getting username and password of user connecting to devices 
    sys_params["wsa_user"] = input("Input user name used to access API and collect information from devices: ")    
    sys_params["wsa_pass"] = getpass()    

    return sys_params, device_list

def store_output(reachable_devices, unreachable_devices):
  """
  Function that stores complete command output for all reachable devices and appends the list of unreacable devices.
  """
  if (sys_params["debug"]):
    print("\nPripremljeni device i system podaci (def(store_output))")
    print (sys_params)
    print (device_list)
  output_filename=sys_params["filename"]+"_"+time.strftime("%Y-%m-%d_%H-%M")+".out"    
  with open(output_filename, 'w') as hostoutputfile:    
    if (sys_params["debug"]):
      print ("Sljedeci podaci biti ce spremljeni u datoteku {}".format(output_filename))
      print("\nIspis snimljenih podataka (def(store_output))")
      for wsa_device in reachable_devices: 
        print(wsa_device)
        print(reachable_devices[wsa_device])
      print(unreachable_devices)
    hostoutputfile.write("Popis WSA uredjaja s podacima\r\n")
    for wsa_device in reachable_devices:                
      hostoutputfile.write(reachable_devices[wsa_device]["product_instance_name"])
      hostoutputfile.write(": ")
      hostoutputfile.write(wsa_device) 
      hostoutputfile.write("\r\n")
      hostoutputfile.write(reachable_devices[wsa_device]["smart_lic_status"]) 
      hostoutputfile.write(": ")
      hostoutputfile.write(reachable_devices[wsa_device]["authorization_status"]) 
      hostoutputfile.write("\r\n\r\n")
    hostoutputfile.write("\r\nPopis nedostupnih uredjaja\r\n")
    for device in unreachable_devices:
      hostoutputfile.write(device)

def print_output(reachable_devices, unreachable_devices):
  """
  Function that prints on screen complete command output for all reachable devices and appends the list of unreacable devices.
  """
  if (sys_params["debug"]):
    print("\nIspis snimljenih podataka (def(print_output))")
    print(reachable_devices)
    print(unreachable_devices)
  print("\r\nPopis uredjaja s podacima\r\n")
  for wsa_device in reachable_devices:                
    print(reachable_devices[wsa_device]["product_instance_name"] + ": " + wsa_device)
    #print(": ")
    #print(wsa_device) 
    #print("\r\n")
    print(reachable_devices[wsa_device]["smart_lic_status"]) 
    #print("\r\n")
    print(reachable_devices[wsa_device]["authorization_status"]) 
    print("\r\n")
  print("\r\nPopis nedostupnih uredjaja\r\n")
  print(unreachable_devices)

def get_wsa_data(wsa_device, reachable_devices, unreachable_devices, wsa_api_command):
  """
  Function that authenticates to Cisco WSA device and gets data related to requested API command.
  """
  global sys_params, device_list
  if (sys_params["debug"]):
    print("\nPripremljeni device i system podaci (def(get_wsa_data))")
    print (sys_params)
    print (device_list)
  print("\n\nDoing WSA device {} with IP {}\n\n\n".format(device_list[wsa_device]["hostname"], wsa_device))
  auth_payload = generate_auth_data()
  try:
    auth_secure_url = "https://"+wsa_device+BASE_SECURE_PORT+AUTH_URI
    response = requests.post(auth_secure_url, data=auth_payload, verify=False, timeout=(30,10))
    response.raise_for_status()
    #print_response(response)
    if response.status_code == 200:
      token=response.json()['data']['jwtToken']
      if sys_params["debug"]:
        print ("{}Dobiveni token za {} uredjaj je {}".format("\n",wsa_device,token))
    else:
      continue_error("Nesto je fulano, greska {}".format(requests.status_codes))
    if sys_params["debug"]:
      print_response(response)
    #priprema za dohvat podataka
    headers = {'jwttoken': token, 'Content-Type': 'application/json'}
    match sys_params["command"]:
      case "license":
        cmd_secure_url = "https://"+wsa_device+BASE_SECURE_PORT+wsa_api_command
        response = requests.get(cmd_secure_url, headers = headers, verify=False, timeout=(30,10))
        response.raise_for_status()
        if sys_params["debug"]:
          print("\nThis is the response from device {} (def(main))".format(wsa_device))
          print_response(response)
        reachable_devices[wsa_device]=response.json()
      case _:
        unreachable_devices.append(wsa_device)
        continue_error("Command not implemented!")
  except requests.exceptions.Timeout as e:
    unreachable_devices.append(wsa_device)
    continue_error("WSA uredjaj {} nedostupan".format(wsa_device))
  except requests.exceptions.ConnectionError as e:
    unreachable_devices.append(wsa_device)
    continue_error("WSA uredjaj {} nedostupan".format(wsa_device))
  except requests.exceptions.ConnectTimeout as e:
    unreachable_devices.append(wsa_device)
    continue_error("WSA uredjaj {} nedostupan".format(wsa_device))
  except requests.exceptions.RequestException as e:
    if response.status_code == 404:
      unreachable_devices.append(wsa_device)
      print(response.url)
      continue_error("No such URI!")
    else:
      print_response(response)
      exit_error(e)
  except urllib3.exceptions.NewConnectionError as e:
    unreachable_devices.append(wsa_device)
    continue_error("WSA uredjaj {} nedostupan".format(wsa_device))
  except urllib3.exceptions.ConnectTimeoutError as e:
    unreachable_devices.append(wsa_device)
    continue_error("WSA uredjaj {} nedostupan".format(wsa_device))      
  except ConnectionRefusedError as e:
    unreachable_devices.append(wsa_device)
    continue_error("WSA uredjaj {} nedostupan".format(wsa_device))          
  except TimeoutError as e:
    unreachable_devices.append(wsa_device)
    continue_error("WSA uredjaj {} nedostupan".format(wsa_device))
  except ValueError as e:
    if response.headers['Content-Type'] == 'text/plain':
      unreachable_devices.append(wsa_device)
      print(response.text)
      continue_error("Ocito nije JSON!")        
    else:
      exit_error(e)
  except KeyError as e:
    exit_error(e)  

def main(argumentList):
  """
  Main code that uses API calls to get info from Cisco WSA devices
  """
  try:
    cmd_options, cmd_values = getopt.getopt(argumentList, "hdj:c:i:", ["help","debug","json=","command=","ip="])
  except getopt.GetoptError:
    exit_error("Invalid input option!")
  logging.basicConfig(filename='wsa-api.log', level=logging.DEBUG)
  #global sys_params = {} # popis parametara komunikacije s WSA uredjajima
  #global device_list = {} # popis svih WSA uredjaja s parametrima
  reachable_devices = {} # direktorij uredjaja sa kojih je dobiven odgovor yajedno sa odgovorom
  unreachable_devices = [] # popis WSA uredjaja koji su zbog raznih razloga nedostupni
  if prepare_device_data(cmd_options):
    if (sys_params["debug"]):
      print("\nPripremljeni device i system podaci (def(main))")
      print (sys_params)
      print (device_list)
    for wsa_device in device_list:
      if device_list[wsa_device]["listed"] == "yes":
        get_wsa_data(wsa_device, reachable_devices, unreachable_devices, cmd_list[sys_params["command"]])
      else:
        unreachable_devices.append(wsa_device)  
    #print("Uredjaji sa odgovorima: {}".format(reachable_devices))
    #print("Nedostupni uredjaji: {}".format(unreachable_devices))
    print_output(reachable_devices, unreachable_devices)
    store_output(reachable_devices, unreachable_devices)
  else:
    exit_error("Device data preparation unrecoverable error!")

if __name__ == "__main__":
  main(sys.argv[1:])