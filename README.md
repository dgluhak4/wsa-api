Script uses Cisco Web Security Appliance API to connect to Cisco WSA devices, gets some info and saves the output to a file.

Usage: wsa-api.py [-d] <single_device> [-j] <json_list_of_devices> [-c] <command>  [OPTIONs]\r\n\r\n
COMMANDS:\r\n
-h --help Help screen\r\n
-g --debug Additional debug info\r\n
-d --connect IP address of the single WSA device\r\n
-j --json json formated file with list of WSA devices and respected commands (mandatory)\r\n
-c --command single command to execute (mandatory)\r\n