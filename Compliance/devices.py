import napalm 
import log_runner
import stig_parser
import globals

class CiscoRouterIOSXE:
    
    def __init__(self, hostname, username, password,ipv4_address):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.ipv4_address = ipv4_address

    def connect(self):
        driver = napalm.get_network_driver('ios')
        device = driver(self.hostname, self.username, self.password)
        device.open()
        return device

    def get_interfaces(self, device_connection):
        interfaces = device_connection.get_interfaces()
        return interfaces

    def get_interfaces_ip(self, device_connection):
        interfaces_ip = device_connection.get_interfaces_ip()
        return interfaces_ip

    def get_mac_address_table(self, device_connection):
        mac_address_table = device_connection.get_mac_address_table()
        return mac_address_table

    def get_arp_table(self, device_connection):
        arp_table = device_connection.get_arp_table()
        return arp_table

    def get_ntp_peers(self, device_connection):
        ntp_peers = device_connection.get_ntp_peers()
        return ntp_peers

    def get_ntp_servers(self, device_connection):
        ntp_servers = device_connection.get_ntp_servers()
        return ntp_servers

    def get_ntp_stats(self, device_connection):
        ntp_stats = device_connection.get_ntp_stats()
        return ntp_stats

    def get_interfaces_counters(self, device_connection):
        interfaces_counters = device_connection.get_interfaces_counters()
        return interfaces_counters

    def get_users(self, device_connection):
        users = device_connection.get_users()
        return users

    def get_bgp_neighbors(self, device_connection):
        bgp_neighbors = device_connection.get_bgp_neighbors()
        return bgp_neighbors

    def get_environment(self, device_connection):
        environment = device_connection.get_environment()
        return environment

    def get_lldp_neighbors(self, device_connection):
        lldp_neighbors = device_connection.get_lldp_neighbors()
        return lldp_neighbors

    def get_lldp_neighbors_detail(self, device_connection):
        lldp_neighbors_detail = device_connection.get_lldp_neighbors_detail()
        return lldp_neighbors_detail

    def get_interfaces_ip(self, device_connection):
        interfaces_ip = device_connection.get_interfaces_ip()

    def get_config(self, device_connection):
         config = device_connection.get_config(retrieve='running', full=True)
         return config

    def run_compliance_ndm(self, device_connection): # TODO: Make sure to loop through ckl
        CHECKLIST = "CiscoRouterIOSXE.ckl"
        
        log_runner.log_message(f"Opening checklist...{CHECKLIST}")
        checklist = stig_parser.open_checklist(CHECKLIST)

        log_runner.log_message(f"Setting hostname on checklist : {self.hostname}")
        stig_parser.set_hostname(self.hostname, checklist["root"], checklist["tree"])

        log_runner.log_message(f"Setting IPv4 address on checklist : {self.ipv4_address}")
        stig_parser.set_ipv4_address(self.ipv4_address, checklist["root"], checklist["tree"])

        log_runner.log_message(f"Command Run on Device {self.hostname}: show running-config all") 
        running_config = self.get_config(self, device_connection)
        
        # 000010 - VTY Lines
        log_runner.log_message("Evaulating Vuln 000010")
        

        

class CiscoSwitchIOSXE:
     CHECKLIST = "CiscoSwitchIOSXE"
     def __init__(self, hostname, username, password):
         self.hostname = hostname
         self.username = username
         self.password = passwor    
     def connect(self):
         driver = napalm.get_network_driver('ios')
         device = driver(self.hostname, self.username, self.password)
         device.open()
         return devic   
     def get_interfaces(self, device_connection):
         interfaces = device_connection.get_interfaces()
         return interface   
     def get_interfaces_ip(self, device_connection):
         interfaces_ip = device_connection.get_interfaces_ip()
         return interfaces_i    
     def get_mac_address_table(self, device_connection):
         mac_address_table = device_connection.get_mac_address_table()
         return mac_address_tabl    
     def get_arp_table(self, device_connection):
         arp_table = device_connection.get_arp_table()
         return arp_tabl    
     def get_ntp_peers(self, device_connection):
         ntp_peers = device_connection.get_ntp_peers()
         return ntp_peer    
     def get_config(self, device_connection):
         config = device_connection.get_config(retrieve='running', full=True)
         return config

   

