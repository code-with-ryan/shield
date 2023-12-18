import stig_parser as sp
import napalm
import json
import globals
import log_runner

class Cisco_Router_NDM_IOS_XE:
    def __init__(self, ipv4_address):
        self.ipv4_address = ipv4_address
        self.run_compliance()
        self.checklist_location = "full_location/checklist.ckl"
       
    def run_compliance(self):
        try:
            # Open Connection
            try:
                driver = napalm.get_network_driver("ios")
                device_connection = driver(self.ipv4_address, self.device, globals.username, globals.password)
                device_connection.open()
            except Exception as e:
                print(f"An error occurred while opening the connection: {e}")
            
            # Get Device Facts
            self.device = device_connection.get_facts()["hostname"]

            # Get Show Run 
            self.show_run = device_connection.cli(["show run all"])

            # Open Checklist
            self.checklist = sp.open_checklist(self.checklist_location)
            
            # Set Hostname
            sp.set_hostname(self.device, self.checklist["root"], self.checklist["tree"])
            
            # Set IPv4 Address
            sp.set_ipv4_address(device_connection.get_interfaces_ip(), self.checklist["root"], self.checklist["tree"])

            # Run Compliance Checks
            self.V215807()
            self.V215808()
            self.V215809()
            self.V215810()
            self.V215811()
            self.V215812()
            self.V215813()
            self.V215814()

        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
        
        finally:
            # Save Checklist
            sp.save_checklist(self.checklist["tree"], self.device)

            # Close Connection
            device_connection.close()

    def V215807(self):
        comments = []
        try:
            pass
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")   
    def V215808(self):
        try:
            required_config_items = ["archive", "log config", "logging enable"]
            non_compliant_config_items = []
            comments = []
            self.commands = ['show run | s archive']
            archive_configuration = self.device_connection.cli(self.commands)  
            for item in required_config_items:
                if item not in archive_configuration:
                    non_compliant_config_items.append(item)

            if len(non_compliant_config_items) > 0:
                comments.append(f"Non-compliant configuration items: {non_compliant_config_items}")
                sp.set_vulnerability_status("V-215808", sp.VALID_STATUS['OPEN'], comments, checklist["root"], checklist["tree"])
            else:
                comments.append("All required configuration items are present.\n {archive_configuration}}")
                sp.set_vulnerability_status("V-215808", sp.VALID_STATUS['NF'], comments, checklist["root"], checklist["tree"]) 

        except Exception as e:
                print(f"An error occurred: {e}") 
    def V215809(self):   
        try:
            comments = []
            comments.append("This vulnerability is a duplicate of V-215808.")
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215809", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def V215810(self):
        try:
            comments = []
            comments.append("This vulnerability is a duplicate of V-215808.")
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215810", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def V215811(self):
        try:
            comments = []
            comments.append("This vulnerability is a duplicate of V-215808.")
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215811", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}") 
    def V215812(self):
        try:
            comments = []
            self.commands = [f"show run | s line vty 0 {globals.MAX_VTY_LINES}"]
            self.response = self.device_connection.cli(self.commands)
            if not "access class" in self.response[self.commands]:
                comments.append(f"Not all VTY lines have an access class configured.")
                comments.append(f"{self.response[self.commands]}")
                sp.set_vulnerability_status("V-215812", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"All VTY lines have an access class configured.")
                comments.append(f"{self.response[self.commands]}")
                sp.set_vulnerability_status("V-215812", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def V215813(self):
        try:
            comments = []
            if not "login block-for 900 attempts 3 within 120" in self.show_run:
                comments.append(f"login block-for 900 attempts 3 within 120 is not properly configured.")
                sp.set_vulnerability_status("V-215813", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def V215814(self):
        try:
            comments = []
            self.commands = ["show banner login"]
            banner = self.device_connection.cli(self.commands)
            if not banner:
                comments.append(f"A login banner is not configured.")
                sp.set_vulnerability_status("V-215814", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"A login banner is configured.")
                comments.append(f"{banner}")
                sp.set_vulnerability_status("V-215814", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def V215815(self):
        try:
            comments = ["This vulnerability is a duplicate of V-215808."]
            # duplicate of 215808
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215815", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def V215816(self):
        comments = []
        if not "service timestamps log datetime" in self.show_run:
            comments.append(f"service timestamps log datetime is not configured.")
            sp.set_vulnerability_status("V-215816", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
        else:
            comments.append(f"service timestamps log datetime is configured.")
            sp.set_vulnerability_status("V-215816", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
    def V215817(self):
        pass