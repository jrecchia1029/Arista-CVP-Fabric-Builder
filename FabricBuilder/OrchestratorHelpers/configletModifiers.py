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

def removeVlansFromVlanConfig(vlans_to_remove, vlan_config):
    '''
    Removes the vlans listed in vlans_to_remove ([list]) along with their configuration from the vlan_config
    '''
    new_config = ""
    #Break vlan_config into separate parts
    vlan_definition_config_list = []
    svi_config_list = []
    vxlan_config = ""
    bgp_config = ""
    for section in re.split(r'\n!\n', vlan_config):
        # print(section)
        # print("\n")
        if re.match(r'^(?i)vlan\s*\d+', section):
            vlan_definition_config_list.append(section + "\n!\n")
        elif re.match(r'^(?i)interface\s*Vlan\s*\d+', section):
            svi_config_list.append(section + "\n!\n")
        elif re.match(r'^(?i)interface\s*Vxlan\s*\d+', section):
            vxlan_config += section + "\n!\n"
        elif re.match(r'^(?i)router\s+bgp\s+\d+', section):
            bgp_config += section + "\n!\n"

    vlan_definition_config = ""
    for vlan_definition in vlan_definition_config_list:
        remove_vlan = False
        for vlan_to_remove in vlans_to_remove:
            if re.search("(?i)vlan\s*{}".format(vlan_to_remove), vlan_definition):
                remove_vlan = True
                break
        if remove_vlan == False:
            vlan_definition_config += vlan_definition

    svi_config = ""
    for svi in svi_config_list:
        remove_svi = False
        for vlan_to_remove in vlans_to_remove:
             if re.search("(?i)interface\s+vlan\s*{}".format(vlan_to_remove), svi):
                remove_svi = True
                break
        if remove_svi == False:
            svi_config += svi

    vxlan_config_lines = vxlan_config.split("\n")
    vxlan_config = ""
    for i, line in enumerate(vxlan_config_lines):
        remove_vlan_to_vni_mapping = False
        for vlan_to_remove in vlans_to_remove:
             if re.search("(?i)vxlan\s+vlan\s+{}".format(vlan_to_remove), line):
                remove_vlan_to_vni_mapping = True
                break
        if remove_vlan_to_vni_mapping == False:
            vxlan_config += line + "\n"

    bgp_config_lines = []
    tmp_bgp_config_lines = bgp_config.strip().split("\n")
    bgp_config_lines.append(tmp_bgp_config_lines.pop(0))
    bgp_config_lines.append(tmp_bgp_config_lines.pop(-1))
    tmp_bgp_config = "\n".join(tmp_bgp_config_lines)
    
    mac_vrf_configs = re.split(r'!\n', tmp_bgp_config)
    for mac_vrf_config in mac_vrf_configs:
        remove_mac_vrf = False
        for vlan_to_remove in vlans_to_remove:
            if re.search("(?i)vlan\s*{}".format(vlan_to_remove), mac_vrf_config):
                remove_mac_vrf = True
                break
        if remove_mac_vrf == False:
            bgp_config_lines.insert(-1, mac_vrf_config + "!")
    bgp_config = "\n".join(bgp_config_lines)

    return vlan_definition_config.strip() + "\n" + svi_config.strip() + "\n" + vxlan_config.strip() + "\n" + bgp_config.strip()