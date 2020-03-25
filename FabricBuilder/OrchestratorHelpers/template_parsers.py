import io, csv, xlrd
from OrchestratorHelpers.leaf import Leaf
from OrchestratorHelpers.spine import Spine
from collections import OrderedDict

def parseLeafInfoExcel(leaf_info_file):
    leafs = []
    workbook = xlrd.open_workbook(leaf_info_file)
    worksheet = workbook.sheet_by_name("Leaf Info")
    first_row = [] # The row where we stock the name of the column
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col) )
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        leaf_info = {}
        for col in range(worksheet.ncols):
            leaf_info[first_row[col]]=worksheet.cell_value(row,col)
        serial_number = leaf_info["Serial Number"].strip()
        container_name = leaf_info["Container Name"].strip()
        hostname = leaf_info["Hostname"].strip()
        mgmt_address = leaf_info["Management IP"].strip()
        mgmt_interface = leaf_info["Management Interface"].strip()
        mlag_peer = leaf_info["MLAG Peer"].strip()
        mlag_interfaces = [iface.strip() for iface in leaf_info["MLAG Interfaces"].split(",")]
        asn = int(leaf_info["ASN"]) if leaf_info["ASN"] != "" else None
        underlay_address = leaf_info["Underlay Loopback Address"].strip()
        overlay_address = leaf_info["Overlay Loopback Address"].strip()
        spine_connection_info = {}
        spine_connection_info[1] = { "local": {"Interface": leaf_info["Spine 1 - Local Interface"].strip(),"IP Address": leaf_info["Spine 1 - Local IP Address"].strip()},
            "remote":{"Interface": leaf_info["Spine 1 - Remote Interface"].strip(),"IP Address": leaf_info["Spine 1 - Remote IP Address"].strip(), "Hostname": None}}
        
        spine_connection_info[2] = { "local": {"Interface": leaf_info["Spine 2 - Local Interface"].strip(),"IP Address": leaf_info["Spine 2 - Local IP Address"].strip()},
            "remote":{"Interface": leaf_info["Spine 2 - Remote Interface"].strip(),"IP Address": leaf_info["Spine 2 - Remote IP Address"].strip(), "Hostname": None}}

        spine_connection_info[3] = { "local": {"Interface": leaf_info["Spine 3 - Local Interface"].strip(),"IP Address": leaf_info["Spine 3 - Local IP Address"].strip()},
            "remote":{"Interface": leaf_info["Spine 3 - Remote Interface"].strip(),"IP Address": leaf_info["Spine 3 - Remote IP Address"].strip(), "Hostname": None}}

        spine_connection_info[4] = { "local": {"Interface": leaf_info["Spine 4 - Local Interface"].strip(),"IP Address": leaf_info["Spine 4 - Local IP Address"].strip()},
            "remote":{"Interface": leaf_info["Spine 4 - Remote Interface"].strip(),"IP Address": leaf_info["Spine 4 - Remote IP Address"].strip(), "Hostname": None}}

        nat_address = leaf_info["NAT Address"].strip() if leaf_info["NAT Address"].strip() != "" else None
        image_bundle = leaf_info["Image Bundle"].strip() if leaf_info["Image Bundle"].strip() != "" else None
        leafs.append(Leaf(serial_number, container_name, hostname, mgmt_address, mgmt_interface,
        mlag_peer, mlag_interfaces, asn, underlay_address, overlay_address, spine_connection_info, nat_address, image_bundle
        ))
    return leafs

def parseSpineInfoExcel(spine_info_file):
    spines = []
    workbook = xlrd.open_workbook(spine_info_file)
    worksheet = workbook.sheet_by_name("Spine Info")
    first_row = [] # The row where we stock the name of the column
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col) )
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        spine_info = {}
        for col in range(worksheet.ncols):
            spine_info[first_row[col]]=worksheet.cell_value(row,col)
        serial_number = spine_info["Serial Number"].strip()
        container_name = spine_info["Container Name"].strip()
        hostname = spine_info["Hostname"].strip()
        mgmt_address = spine_info["Management IP"].strip()
        mgmt_interface = spine_info["Management Interface"].strip()
        asn = int(spine_info["ASN"])
        asn_range = str(spine_info["ASN Range"]).strip()
        underlay_address = spine_info["Underlay Loopback Address"].strip()
        transit_ip_range = str(spine_info["Transit IP Range"]).strip()
        underlay_loopback_ip_range = str(spine_info["Underlay Loopback IP Range"]).strip()
        ecmp_paths = int(spine_info["ECMP Paths"])
        image_bundle = spine_info["Image Bundle"].strip() if spine_info["Image Bundle"].strip() != "" else None
        spines.append(Spine(serial_number, container_name, hostname,
            mgmt_address, mgmt_interface, asn, asn_range, underlay_address,
            transit_ip_range, underlay_loopback_ip_range, ecmp_paths, image_bundle))
    return spines    

def parseGeneralInfoExcel(general_info_file):
    general_info = {}
    workbook = xlrd.open_workbook(general_info_file)
    worksheet = workbook.sheet_by_name("Global Variables L3LS")
    vlan_info = parseVlans(general_info_file)
    general_info["Vlans"] = vlan_info
    vrf_info = parseVrfs(general_info_file)
    general_info["Vrfs"] = vrf_info
    cvp_addresses = parseCVPAddresses(general_info_file)
    general_info["CVP"] = {}
    general_info["CVP"]["CVP Addresses"] = cvp_addresses
    section = None
    section_info = None
    prev_line_blank = True
    for row in range(1, worksheet.nrows):
        if worksheet.cell(row, 0).value == "":
            prev_line_blank = True
            continue
    
        if  worksheet.cell(row, 1).value == "" and prev_line_blank == True:
            prev_line_blank = False
            # print section
            # print section_info
            if section is not None:
                general_info[section] = section_info
            
            section = worksheet.cell(row, 0).value
            section_info = {}
        
        else:
            prev_line_blank = False
            for col in range(worksheet.ncols):
                cell = worksheet.cell(row, col)
                if col == 0:
                    key = cell.value
                elif col == 1:
                    value = cell.value
            section_info[key] = value
    #Add last section
    general_info[section] = section_info
    import json
    print(json.dumps(general_info, indent=2))
    return general_info
    
def parseVlans(general_info_file):
    vlan_info = OrderedDict()
    vlans = []
    workbook = xlrd.open_workbook(general_info_file)
    worksheet = workbook.sheet_by_name("Vlans")
    first_row = [] # The row where we stock the name of the column
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col) )
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        vlan = {}
        for col in range(worksheet.ncols):
            vlan[first_row[col]]=worksheet.cell_value(row,col)
        vlans.append(vlan)
    for vlan in vlans:
        vlan_info[int(vlan["Vlan"])] = {
            "SVI Address": vlan["SVI Address"].strip(),
            "Name": vlan["Name"].strip(),
            "Vrf": vlan["Vrf"].strip(),
            "Stretched": vlan["Stretched"],
            "VNI": vlan["VNI"],
            "Route Distinguisher": vlan["Route Distinguisher"],
            "DHCP Helper Addresses": [address.strip() for address in vlan["DHCP Helper Addresses"].split(",")]
            }
    return vlan_info

def parseVrfs(general_info_file):
    vrf_info = OrderedDict()
    vrfs = []
    workbook = xlrd.open_workbook(general_info_file)
    worksheet = workbook.sheet_by_name("Vrfs")
    first_row = [] # The row where we stock the name of the column
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col))
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        vlan = {}
        for col in range(worksheet.ncols):
            vlan[first_row[col]]=worksheet.cell_value(row,col)
        vrfs.append(vlan)
    for vrf in vrfs:
        vrf_info[vrf["VRF Name"].strip()] = {
            "Route Distinguisher": vrf["Route Distinguisher"].strip(),
            "Route Target": vrf["Route Target"].strip(),
            "Vlan": int(vrf["Vlan"]),
            "SVI Address Range": vrf["SVI Address Range"].strip(),
            "VNI": int(vrf["VNI"])
        }
    return vrf_info

def parseCVPAddresses(general_info_file):
    cvp_info = {}
    cvp_addresses = []
    workbook = xlrd.open_workbook(general_info_file)
    worksheet = workbook.sheet_by_name("CVP Info")
    for row in range(1, worksheet.nrows):
        cvp_info[worksheet.cell_value(row, 0)] = worksheet.cell_value(row, 1)
    for node, address in cvp_info.items():
        if address is not None and address != "":
            cvp_addresses.append(address)

    if len(cvp_addresses) == 3:
        return cvp_addresses

    elif len(cvp_addresses) >= 1 and len(cvp_addresses) < 3:
        return [cvp_addresses[0]]
    else:
        return None

def parseDay2Targets(general_info_file):
    workbook = xlrd.open_workbook(general_info_file)
    worksheet = workbook.sheet_by_name("Day 2 Target Devices")
    first_row = [] # The row where we stock the name of the column
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col))
    devices = []
    for row in range(1, worksheet.nrows):
        leaf_info = {}
        for col in range(worksheet.ncols):
            leaf_info[first_row[col]]=worksheet.cell_value(row,col)
        serial_number = leaf_info["Serial Number"]
        hostname = leaf_info["Hostname"]
        mgmt_address = leaf_info["Management IP"]
        devices.append(Leaf(serial_number, None, hostname, mgmt_address, None,
                            None, None, None, None, None, None, None, None))
    return devices
