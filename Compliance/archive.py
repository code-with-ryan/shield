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
           

        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
        
        finally:
            # Save Checklist
            sp.save_checklist(self.checklist["tree"], self.device)

            # Close Connection
            device_connection.close()

    def CISC_ND_000010(self):
        comments = []
        try:
            pass
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")   
    def CISC_ND_000090(self):
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
    def CISC_ND_000100(self):   
        try:
            comments = []
            comments.append("This vulnerability is a duplicate of V-215808.")
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215809", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000110(self):
        try:
            comments = []
            comments.append("This vulnerability is a duplicate of V-215808.")
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215810", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000120(self):
        try:
            comments = []
            comments.append("This vulnerability is a duplicate of V-215808.")
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215811", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}") 
    def CISC_ND_000140(self):
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
    def CISC_ND_000150(self):
        try:
            comments = []
            if not "login block-for 900 attempts 3 within 120" in self.show_run:
                comments.append(f"login block-for 900 attempts 3 within 120 is not properly configured.")
                sp.set_vulnerability_status("V-215813", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000160(self):
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
    def CISC_ND_000210(self):
        try:
            comments = ["This vulnerability is a duplicate of V-215808."]
            # duplicate of 215808
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215815", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000280(self):
        comments = []
        if not "service timestamps log datetime" in self.show_run:
            comments.append(f"service timestamps log datetime is not configured.")
            sp.set_vulnerability_status("V-215816", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
        else:
            comments.append(f"service timestamps log datetime is configured.")
            sp.set_vulnerability_status("V-215816", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
    def CISC_ND_000290(self):
        try: 
            comments =[]
            firewall_policies = self.device_connection.get_firewall_policies()
            for policy in firewall_policies:
                if policy["action"] == "deny" and not policy["log"] == "all":
                    comments.append(f"Firewall policy {policy['name']} does not log all denied packets.")
                    sp.set_vulnerability_status("V-215817", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])

            if sp.get_vulnerability_status() == sp.VALID_STATUS['NotAFinding']:
                comments.append(f"All firewall policies log all denied packets.")
                sp.set_vulnerability_status("V-215817", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000330(self):
        try:
            comments = ["This vulnerability is a duplicate of V-215808."]
            status = sp.get_vulnerability_status("V-215808", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215818", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000380(self):
        pass
    def CISC_ND_000390(self):
        try:
            comments = []
            if not "file privilege 15" in self.show_run:
                comments.append(f"Privilege level 15 is not configured.")
                sp.set_vulnerability_status("V-215819", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000460(self):
        try:
            #duplicate of 000390
            comments = ["This vulnerability is a duplicate of V-215819."]
            status = sp.get_vulnerability_status("V-215819", self.checklist["root"], self.checklist["tree"])
            sp.set_vulnerability_status("V-215820", status, comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000470(self):
        try:
            comments = []
            commands = ["boot network", "ip boot server", "ip bootp server", "ip dns server", "ip identd", "ip finger", "ip http server", "ip rcmd rcp-enable", "ip rcmd rsh-enable", "service config", "service finger", "service tcp-small-servers", "service udp-small-servers", "service pad", "service call-home"]
            for command in commands:
                if command in self.show_run:
                    comments.append(f"{command} is configured.")
                    sp.set_vulnerability_status("V-215821", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            
            if not sp.get_vulnerability_status() == sp.VALID_STATUS["OPEN"]:
                comments.append(f"All services are disabled.")
                sp.set_vulnerability_status("V-215821", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000490(self):
        try: 
            comments = []
            users = self.device_connection.get_users()
            if users.count() > 1:
                comments.append(f"More than one user is configured.")
                sp.set_vulnerability_status("V-215822", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"Only one user is configured.")
                sp.set_vulnerability_status("V-215822", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000550(self):
        try:
            comments =[]
            commands = ["show run | section aaa common-criteria policy"]
            self.response = self.device_connection.cli(commands)
            if not "min-length 15" in self.response:
                comments.append(f"Minimum password length is not configured.")
                sp.set_vulnerability_status("V-215823", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"Minimum password length is configured.")
                sp.set_vulnerability_status("V-215823", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000570(self):
        try:
            comments =[]
            commands = ["show run | section aaa common-criteria policy"]
            self.response = self.device_connection.cli(commands)
            if not "upper-case 1" in self.response:
                comments.append(f"Minimum upper case characters is not configured.")
                sp.set_vulnerability_status("V-215824", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"Minimum upper case characters is configured.")
                sp.set_vulnerability_status("V-215824", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000580(self):
        try:
            comments =[]
            commands = ["show run | section aaa common-criteria policy"]
            self.response = self.device_connection.cli(commands)
            if not "lower-case 1" in self.response:
                comments.append(f"Minimum lower case characters is not configured.")
                sp.set_vulnerability_status("V-215825", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"Minimum lower case characters is configured.")
                sp.set_vulnerability_status("V-215825", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000590(self):
        try:
            comments =[]
            commands = ["show run | section aaa common-criteria policy"]
            self.response = self.device_connection.cli(commands)
            if not "numeric-count 1" in self.response:
                comments.append(f"Minimum numeric characters is not configured.")
                sp.set_vulnerability_status("V-215826", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"Minimum numeric characters is configured.")
                sp.set_vulnerability_status("V-215826", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000600(self):
        try:
            comments =[]
            commands = ["show run | section aaa common-criteria policy"]
            self.response = self.device_connection.cli(commands)
            if not "special-case 1" in self.response:
                comments.append(f"Minimum special characters is not configured.")
                sp.set_vulnerability_status("V-215827", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"Minimum special characters is configured.")
                sp.set_vulnerability_status("V-215827", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred while running the compliance check: {e}")
    def CISC_ND_000610(self):
        try:
            comments =[]
            commands = ["show run | section aaa common-criteria policy"]
            self.response = self.device_connection.cli(commands)
            if not "char-changes 8" in self.response:
                comments.append(f"Minimum character changes is not configured.")
                sp.set_vulnerability_status("V-215828", sp.VALID_STATUS['OPEN'], comments, self.checklist["root"], self.checklist["tree"])
            else:
                comments.append(f"Minimum character changes is configured.")
                sp.set_vulnerability_status("V-215828", sp.VALID_STATUS['NF'], comments, self.checklist["root"], self.checklist["tree"])
        except Exception as e:
            print(f"An error occurred: {e}")
