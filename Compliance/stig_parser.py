import xml.etree.ElementTree as ET
from datetime import date

TODAY = str(date.today().strftime("%Y-%m-%d"))
STIG_DIRECTORY = "Checklists/"

"""
VALID_STATUS = { # human readable : stig readable
    "Not A Finding" : "NotAFinding",
    "Not Reviewed" : "Not_Reviewed",
    "Not Applicable" : "Not_Applicable",
    "Open" : "OPEN"
}
"""

def open_checklist(filename):
    try:
        tree = ET.parse(STIG_DIRECTORY + filename)
        root = tree.getroot()
        checklist = {"tree" : tree, "root" : root} 
        return checklist
    except Exception as e:
        print(f"An error occurred while opening the checklist: {e}")

def save_checklist(filename, hostname):
    checklist = STIG_DIRECTORY + hostname + "_" + filename
    try:
        filename.write(checklist)
        return True
    except Exception as e:
        print(f"An error occurred while saving the checklist: {e}")
        return False

def get_all_vulnerabilities(root, tree):
    pass

def set_hostname(hostname, root, tree):
    try:
        for host in root.findall(".//HOST_NAME"):
            host.text = hostname
    except Exception as e:
        print(f"An error occurred while setting the hostname: {e}")

def set_ipv4_address(ipv4_address, root, tree):
    try:
        for host in root.findall(".//HOST_IP"):
            host.text = ipv4_address
    except Exception as e:
        print(f"An error occurred while setting the IPv4 address: {e}")

def set_vulnerability_status(vuln_id, status, comments, root, tree): # TODO: Make sure to properly handle opens
    try:
        for child in root.findall(".//VULN"):
            if child.find(".//VULN_ATTRIBUTE").text == "Vuln_Num":
                if child.find(".//ATTRIBUTE_DATA").text == vuln_id:
                    # Finding Details
                    finding_details = child.find("./FINDING_DETAILS")
                    finding_details.text = f"Tool: SHIELD \n Completed: {TODAY} \n Status: {status}"
                    # Finding Status 
                    finding_status = child.find("./STATUS")
                    finding_status.text = status
                    # Finding Comments
                    finding_comments = child.find("./COMMENTS")
                    finding_comments.text = "".join(comments)


    except Exception as e:
        print(f"An error occurred while setting the vulnerability status: {e}")

def get_vulnerability_status(vuln_id, root, tree):
    try:
        for child in root.findall(".//VULN"):
            if child.find(".//VULN_ATTRIBUTE").text == "Vuln_Num":
                if child.find(".//ATTRIBUTE_DATA").text == vuln_id:
                    # Finding Status 
                    finding_status = child.find("./STATUS")
                    return finding_status.text
    except Exception as e:
        print(f"An error occurred while getting the vulnerability status: {e}")

