import re
from collections import OrderedDict

def convert(text):
    return int(text) if text.isdigit() else text.lower()


def alphanum_key(key):
    return [convert(c) for c in re.split('([0-9]+)', str(key))]

def mergeInterfaceConfigs(a, b):
    b_interfaces = [iface.strip("!") for iface in  b.split("\n!\n") ]
    b_interfaces = [iface.strip() for iface in b_interfaces]
    for iface in b_interfaces:
        interface_config = iface.split("\n")
        if interface_config[0] in a:
            continue
        else:
            a += "\n" + iface + "\n!"
    a_interfaces = [iface.strip("!") for iface in  a.split("\n!\n") ]
    a_interfaces = [iface.strip() for iface in a_interfaces]
    interface_names_and_details = {}
    for a in a_interfaces:
        interface_names_and_details[a.split("\n")[0]] = a
    interface_names = sorted(interface_names_and_details.keys(), key=alphanum_key)
    a = []
    for name in interface_names:
        a.append(interface_names_and_details[name])
    a = "\n!\n".join(a)
    return a

def mergeVlanConfigs(a, b):
    vlan_dict = {}
    vlan_instantiation_section = ""
    svi_dict = {}
    svi_section = ""
    vxlan_dict = {}
    vxlan_section = ""
    mac_vrf_dict = {}
    bgp_section = ""

    #Get vlans in configlet B
    b_vlans = re.findall(r'^((vlan\s+\d+)\n(\s+.+\n)*)', b, re.MULTILINE)
    for vlan in b_vlans:
        k = " ".join(vlan[1].split())
        vlan_dict[k] = vlan[0]
    #get vlans in configlet A 
    a_vlans = re.findall(r'^((vlan\s+\d+)\n(\s+.+\n)*)', a, re.MULTILINE)
    for vlan in a_vlans:
        k = " ".join(vlan[1].split())
        vlan_dict[k] = vlan[0]
    
    vlan_dict = order_dict(vlan_dict)
    for config in vlan_dict.values():
        vlan_instantiation_section += config + "!\n"

    # print(vlan_instantiation_section)

    #Get SVIs in configlet B and merge
    b_svis = re.findall(r'^((interface\s+Vlan\s*\d+)\n(\s+.+\n)*)', b, re.MULTILINE)
    for svi in b_svis:
        k = " ".join(svi[1].split())
        if re.match(r'(?i)interface\svlan\s\d+', k):
            k = k[:k.rindex(" ")] + k[k.rindex(" ")+1:]
        svi_dict[k] = svi[0]
    #Get SVIs in configlet A
    a_svis = re.findall(r'^((interface\s+Vlan\s*\d+)\n(\s+.+\n)*)', a, re.MULTILINE)
    for svi in a_svis:
        k = " ".join(svi[1].split())
        if re.match(r'(?i)interface\svlan\s\d+', k):
            k = k[:k.rindex(" ")] + k[k.rindex(" ")+1:]
        svi_dict[k] = svi[0]

    svi_dict = order_dict(svi_dict)
    for config in svi_dict.values():
        svi_section += config + "!\n"
    
    # print(vlan_instantiation_section + svi_section)

    #Get Vxlan to VNI Mappings in configlet B
    b_vxlan_config = re.search(r'^(interface Vxlan\s*1\n(\s+.+\n)*)', b, re.MULTILINE)
    if b_vxlan_config is not None:
        vlan_vni_mappings = re.findall(r'^(\s+vxlan\s+vlan\s+(\d+)\s+vni\s+\d+)', b, re.MULTILINE)
        for mapping in vlan_vni_mappings:
            vxlan_dict[mapping[1]] = mapping[0]
    #Get Vxlan to VNI Mappings in configlet A
    a_vxlan_config = re.search(r'^(interface Vxlan\s*1\n(\s+.+\n)*)', a, re.MULTILINE)
    if a_vxlan_config is not None:
        vlan_vni_mappings = re.findall(r'^(\s+vxlan\s+vlan\s+(\d+)\s+vni\s+\d+)', a, re.MULTILINE)
        for mapping in vlan_vni_mappings:
            vxlan_dict[mapping[1]] = mapping[0]
    vxlan_dict = order_dict(vxlan_dict)
    if len(vxlan_dict.keys()) > 0:
        vxlan_section += "interface Vxlan1\n"
    for config in vxlan_dict.values():
        vxlan_section += config + "\n"
    vxlan_section += "!\n"
    # print(vlan_instantiation_section + svi_section + vxlan_section)

    #Get BGP configuration in configlet B
    bgp_configuration = re.search(r'^(router bgp \d+\n(\s+.+\n)*)', b, re.MULTILINE)
    if bgp_configuration is not None:
        # print(bgp_configuration.group(0))
        bgp_router_statement = bgp_configuration[0].split("\n")[0]
        bgp_configuration =  bgp_configuration[0].split("\n")
        print("\n".join(bgp_configuration))
        bgp_configuration = bgp_configuration[1:-1]
        bgp_configuration = "\n".join(bgp_configuration)
        print(bgp_configuration)
        mac_vrfs = re.split(r'^(?=\s+vlan\s+\d+)', bgp_configuration, 0, re.MULTILINE)
        print(mac_vrfs)
        for mac_vrf in mac_vrfs:
            vlan = re.match(r'^\s+vlan\s+(\d+)', mac_vrf)
            if vlan is not None:
                mac_vrf_dict[vlan.group(1)] = mac_vrf

    bgp_configuration = re.search(r'^(router bgp \d+\n(\s+.+\n)*)', a, re.MULTILINE)
    if bgp_configuration is not None:
        bgp_router_statement = bgp_configuration[0].split("\n")[0]
        bgp_configuration =  bgp_configuration[0].split("\n")
        bgp_configuration = bgp_configuration[1:-1]
        bgp_configuration = "\n".join(bgp_configuration)
        mac_vrfs = re.split(r'^(?=\s+vlan\s+\d+)', bgp_configuration, 0, re.MULTILINE)
        for mac_vrf in mac_vrfs:
            vlan = re.match(r'^\s+vlan\s+(\d+)', mac_vrf)
            if vlan is not None:
                mac_vrf_dict[vlan.group(1)] = mac_vrf

    mac_vrf_dict = order_dict(mac_vrf_dict)
    if len(mac_vrf_dict.keys()) > 0:
        bgp_section += bgp_router_statement + "\n"
    for config in mac_vrf_dict.values():
        config = config.rstrip()
        bgp_section += config + "\n"
    if len(mac_vrf_dict.keys()) > 0:
        bgp_section += "!\n"
    
    return vlan_instantiation_section + svi_section + vxlan_section + bgp_section

def order_dict(dictionary):
    od = OrderedDict()
    key_names = sorted(dictionary.keys(), key=alphanum_key)
    for k in key_names:
        od[k] = dictionary[k]
    return od

