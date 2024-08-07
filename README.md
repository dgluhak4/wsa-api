Script uses Cisco Web Security Appliance API to connect to Cisco WSA devices, gets some info and saves the output u a file

Usage: wsa-api.py [-d] <single_device> [-j] <json_list_of_devices> [-c] <command>  [OPTIONs]
COMMANDS:
-h --help Help screen
-g --debug Additional debug info
-j --json json formated file with list of WSA devices and respected commands (mandatory)
-c --command single command to execute (mandatory)