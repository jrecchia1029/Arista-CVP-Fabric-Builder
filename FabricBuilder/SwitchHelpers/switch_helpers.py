import re, json
from collections import OrderedDict
# from SwitchHelpers.chips import chipModelInfo
# from SwitchHelpers.models import switchModelInfo
import ipaddress
from SwitchHelpers.models import sand_family_model_regexes

def parse_show_interfaces_json(output):
    raw_interface_info = json.loads(output)
    raw_interface_info = raw_interface_info["interfaces"]
    raw_interface_info = OrderedDict(sorted(raw_interface_info.items()))
    list_of_interface_info = []
    for iface, details in raw_interface_info.items():
        interface_details = {}
        interface_details["hardware_type"] = details["hardware"]
        interface_details["description"] = details["description"]
        interface_details["link_status"] = details["interfaceStatus"]
        interface_details["protocol_status"] = details["lineProtocolStatus"]
        interface_details["bia"] = details["burnedInAddress"] if "burnedInAddress" in list(details) else ""
        interface_details["bandwidth"] = details["bandwidth"] 
        interface_details["address"] = details["physicalAddress"] if "physicalAddress" in list(details) else ""
        interface_details["interface"] = details["name"]
        interface_details["mtu"] = details["mtu"]
        interface_details["ip_address"] = details["interfaceAddress"]
        list_of_interface_info.append(interface_details)
    return list_of_interface_info

def sortInterfaceConfig(interfaceSection):
    #Create dictionary where interface names are keys
    interfaces = [iface.strip() for iface in interfaceSection.split("!")]
    interface_dict = {}
    for interface in interfaces:
        iface_name = re.match(r'interface (([a-zA-Z,-]+)([\d,\/]+))', interface)
        if iface_name:
            interface_dict[iface_name.group(1)] = interface
        
    sorted_keys = sorted(list(interface_dict), key=cmp_to_key(interfaceComparator))
       
    config = []
    for key in sorted_keys:
        config.append(interface_dict[key])

    return "\n!\n".join(config) + "\n!\n"

def interfaceComparator(a, b):
    match_a = re.match('\D+', a)
    match_b = re.match('\D+', b)
    if match_a and match_b:
        if match_a.group(0).lower() < match_b.group(0).lower(): return -1
        if match_a.group(0).lower() > match_b.group(0).lower(): return 1
        else:
            if len(match_a.group(0)) < len(a) or len(match_b.group(0)) < len(b):
                return interfaceComparator(a[match_a.end(0):], b[match_b.end(0):])
    match_a = re.match('\d+', a)
    match_b = re.match('\d+', b)
    if match_a and match_b:
        if int(match_a.group(0)) < int(match_b.group(0)): return -1
        if int(match_a.group(0)) > int(match_b.group(0)): return 1
        else:
            if len(match_a.group(0)) < len(a) or len(match_b.group(0)) < len(b):
                return interfaceComparator(a[match_a.end(0):], b[match_b.end(0):])
    return 0

def cmp_to_key(mycmp):
    'Convert a cmp= function into a key= function'
    class K(object):
        def __init__(self, obj, *args):
            self.obj = obj
        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0
        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0
        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0
        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0  
        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0
        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0
    return K

def asn_range_getter(asns):
    asn_ranges = []
    asns = [int(asn) for asn in asns]
    asns = sorted(asns)
    i = 0
    start_asn = None
    last_asn = None
    for asn in asns:
        if start_asn is None:
            start_asn = asn
            last_asn = asn
            continue
        if asn - last_asn > 1:
            if start_asn == last_asn:
                asn_ranges.append(str(start_asn))
            else:
                asn_ranges.append(str(start_asn) + "-" + str(last_asn))
            
            if asn == asns[len(asns)-1]:
                asn_ranges.append(str(asn))
            start_asn = asn
        elif asn == asns[len(asns)-1]:
            if start_asn == asn:
                asn_ranges.append(str(start_asn))
            else:
                asn_ranges.append(str(start_asn) + "-" + str(asn))
        last_asn = asn
            
    return asn_ranges

def check_if_model_uses_chip_in_sand_family(model_name):
    for regex in sand_family_model_regexes:
        if re.search(regex, model_name):
            return True
    return False

