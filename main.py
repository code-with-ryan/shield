from napalm import get_network_driver
import os
from Compliance import stig_parser as parser
from Compliance import checklist_rules as rules
from Compliance import log_handler 

def device_connection(ip_address):
    try:
        driver = get_network_driver('ios')
        
        username = os.environ['USERNAME']
        password = os.environ['PASSWORD']
        
        device = driver(ip_address, username, password)
        device.open()
        
        return device
    except KeyError:
        print("Please set the USERNAME and PASSWORD environment variables.")
        return None
    except Exception as e:
        print(f"An error occurred while trying to connect to the device: {e}")
        return None

def run_compliance(checklist,device):
    rules.CISC_ND_000090(checklist, device)

# main entry of program
def main():
    device = device_connection("")
    
    checklist = parser.open_checklist("Cisco_IOS_XE_STIG_V1R1.ckl")
    
    #prepare checklist
    # Get Device Facts
    hostname = device_connection.get_facts()["hostname"]
    
    # Set Hostname
    parser.set_hostname(hostname, checklist["root"], checklist["tree"])
     
    # Set IPv4 Address
    parser.set_ipv4_address(device_connection.get_interfaces_ip(), checklist["root"], checklist["tree"])
    
    run_compliance(checklist,device)
    
    log_handler.log_message(f"Completed compliance check on  {hostname}.")