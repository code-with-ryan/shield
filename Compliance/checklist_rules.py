def CISC_ND_000090(checklist, device):
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