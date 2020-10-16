#from ntc_templates.parse import parse_output
import SwitchHelpers.switch_helpers as switch_helpers
from SwitchHelpers.chips import chipModelInfo
from SwitchHelpers.models import switchModelInfo
import re, json
from collections import OrderedDict
import ipaddress
 
class Switch():
    """
    Class to act as an EOS Switch object.  Uses Netmiko (SSH) or jsonrpclib (EAPI) to execute switch functions. 
    """
    def __init__(self, ip_address=None, username=None, password=None):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.hostname = None
        self.fqdn = None
        self.serial_number = None
        self.mac_address = None
        self.eos_version = None
        self.model = None
        self.chipset = None
        self.interfaces = None

    def __str__(self):
        output = ""
        output += "Switch: {}\n".format(self.hostname)
        output += "  {:15} {}\n".format("FQDN:", self.fqdn)
        output += "  {:15} {}\n".format("IP address:", self.ip_address)
        output += "  {:15} {}\n".format("MAC address:", self.mac_address)
        output += "  {:15} {}\n".format("EOS version:", self.eos_version)
        output += "  {:15} {}\n".format("Serial Number:", self.serial_number)
        output += "  {:15} {}\n".format("Model:", self.model)
        output += "  {:15} {}\n".format("Chipset:", self.chipset)
        return output

    def send_commands(self, commands, enable=True, method="eapi"):
        """
        Executes commands on an Arista switch

            cmds ( [str] ):  A list of commands to be executed on the switch

            method ( str ): A value that determines what method to send a command
                            Options are:
                                eapi
                                netmiko

            Returns a list of dictionaries with a single key/value pair of command/output

        """
        if method == "ssh":
            return self.send_commands_via_netmiko(commands, enable=enable)
        else:
            return self.send_commands_via_eapi(commands, enable=enable)

    def send_commands_via_eapi(self, commands, enable=True):
        """
        Uses the Server class from jsonrpclib to make API calls to the Arista EAPI running on switches

            cmds ( [str] ):  A list of commands to be executed on the switch

            Returns a list of dictionaries with a single key/value pair of command/output

        """
        import pyeapi

        if type(commands) == str:
            commands = [commands]

        try:
            switch = pyeapi.connect(host=self.ip_address, username=self.username, password=self.password)
            if enable==True:
                commands.insert(0, "enable")
            
            response = switch.execute(commands, encoding="text")
        except Exception as e:
            print(e)
            return None
        else:
            result = []
            tmp_result = response["result"]
            if enable==True:
                tmp_result.pop(0)
            for index, output in enumerate(tmp_result):
                if enable==True:
                    i = index + 1
                for k, v in output.items():
                    result.append({commands[i]:output["output"]})
            return result

    def send_commands_via_netmiko(self, commands, enable=True):

        """
        Uses the Netmiko library to ssh to the Arista switches and sends commands

            cmds ( [str] ):  A list of commands to be executed on the switch

            Returns a list of dictionaries with a single key/value pair of command/output

        """
        from netmiko import ConnectHandler, NetmikoAuthError, NetmikoTimeoutError

        response = []
        try:
            connection = ConnectHandler(device_type="arista_eos", ip=self.ip_address, username=self.username, 
                                        password=self.password, secret=self.password)
        except (NetmikoAuthError, NetmikoTimeoutError, ValueError) as e:
            print(e)
            return None
        else:
            if type(commands) == str:
                commands = [commands]

            if enable == True:
                connection.enable()

            for command in commands:
                output = {command: connection.send_command_timing(command)}
                response.append(output)
            connection.disconnect()
        return response

    def get_facts(self):
        hostname_output = self.send_commands("show hostname | json")[0]["show hostname | json"]
        # print("hostname_output")
        version_output = self.send_commands("show version | json")[0]["show version | json"]
        # print("version_output")
        interface_output = self.send_commands("show interfaces | json")[0]["show interfaces | json"]
        # print("interface_output")
        self.hostname = json.loads(hostname_output)["hostname"]
        self.fqdn = json.loads(hostname_output)["fqdn"]
        self.mac_address = json.loads(version_output)["systemMacAddress"]
        self.serial_number = json.loads(version_output)["serialNumber"]
        self.eos_version = json.loads(version_output)["version"]
        self.model = json.loads(version_output)["modelName"]
        try:
            self.chipset = switchModelInfo["-".join(json.loads(version_output)["modelName"].split("-")[:-1])]["chipset"] if json.loads(version_output)["modelName"] != 'vEOS' else 'vEOS'
        except:
            self.chipset = None
        self.interfaces = json.loads(interface_output)["interfaces"]

    def update_chipset_by_model(self):
        try:
            self.chipset = switchModelInfo[self.model]["chipset"] if self.model != 'vEOS' else 'vEOS'
        except:
            self.chipset = None
        if self.chipset is None:
            try:
                self.chipset = switchModelInfo["-".join(self.model.split("-")[:-1])]["chipset"] if self.model != 'vEOS' else 'vEOS'
            except:
                self.chipset = None

    def build_management_configlet(self, hostname, management_ip, default_route=None, management_interface="Management1", 
                                vrf="default", vrf_rd="1:1", cvp_node_addresses=None, cvp_ingest_key=None):
        '''
        Returns a potential management configuration based on input arguments

        Args:
            management_ip (str) --> management IP Address in CIDR format ex: (10.0.0.2/24)
            management_interface (str) --> interface to use for management
            default_route (str)  --> ip address of default gateway ex: (10.0.0.1)
            vrf (str) --> name of management vrf
            vrf_rd (str) --> management vrf route-distinguisher
            cvp_node_addresses ( ["cvp addresses"] ) --> array of strings of cvp addresses i.e. ["10.0.0.1"]

        Returns:
            Management configlet (str)
        '''
        management_configlet = []

        hostname_section  = ["hostname {}".format(hostname)]
        terminattr_section = []
        vrf_definition_section = []
        interface_section = []
        api_section = []
        ip_routing_section = []

        if cvp_node_addresses is not None:
            if cvp_ingest_key is None:
                cvp_ingest_key = ""
            ingestgrpcurl = ""
            for node in cvp_node_addresses:
                ingestgrpcurl += "{}:9910,".format(node)
            ingestgrpcurl = ingestgrpcurl[:-1]
            terminattr_section.append("daemon TerminAttr")
            terminattr_section.append("     exec /usr/bin/TerminAttr -ingestgrpcurl={} -cvcompression=gzip -ingestauth=key,{} -smashexcludes=ale,flexCounter,hardware,kni,pulse,strata -ingestexclude=/Sysdb/cell/1/agent,/Sysdb/cell/2/agent -ingestvrf={} -taillogs ".format(ingestgrpcurl, cvp_ingest_key, vrf))
            terminattr_section.append("     no shutdown")
            terminattr_section.append("!")


        interface_section.append("interface {}".format(management_interface))
        interface_section.append("   ip address {}".format(management_ip))

        api_section.append("management api http-commands")
        api_section.append("   no shutdown")

        ip_routing_section.append("!")

        if vrf != "default":
            vrf_definition_section.append("vrf instance {}\n".format(vrf))
            vrf_definition_section.append("   rd {}\n".format(vrf_rd))

            interface_section.insert(1, "   vrf {}".format(vrf))

            api_section.append("   !")
            api_section.append("   vrf {}".format(vrf))
            api_section.append("      no shutdown")

            ip_routing_section.append("no ip routing vrf {}".format(vrf))
            ip_routing_section.insert(0, "ip route vrf {} 0.0.0.0/0 {}".format(vrf, default_route))
        else:
            ip_routing_section.insert(0, "ip route 0.0.0.0/0 {}".format(default_route))
        
        hostname_section = "\n".join(hostname_section)
        terminattr_section = "\n".join(terminattr_section)
        vrf_definition_section = "\n".join(vrf_definition_section) if len(vrf_definition_section) > 0 else ""
        interface_section = "\n".join(interface_section)
        api_section = "\n".join(api_section)
        ip_routing_section = "\n".join(ip_routing_section)

        management_configlet = [terminattr_section, hostname_section, vrf_definition_section, interface_section, api_section, ip_routing_section]

        return "\n!\n".join(management_configlet)


    #svi_address range has to be unicode for python 2
    def build_mlag(self, role, mlag_domain_id="MLAG_DOMAIN", mlag_svi_address_range="172.21.17.254/31", number_of_interfaces=2, interfaces=None,
                    port_channel=2000, vlan=4094, trunk_group_name="MLAG_Peer", virtual_mac="00:1c:73:00:00:34", dual_primary_detection_delay=5,
                    dual_primary_detection_action=None, heartbeat_address=None, heartbeat_vrf=None, stp_mode="rapid-pvst"):
        """
        Returns a potential mlag configuration based on input arguments.
 
        Args:
            mlag_domain_id (str) --> name of mlag domain-id
            role ( str ) -> "primary" or "secondary"  Does NOT literally define primary or secondary role
            svi_address_range ( str ) -> format: "a.b.c.d/xy" - address for SVI which will be peer link IP address 
            port_channel ( int ) -> port channel interface number for MLAG peer link
            vlan ( int ) -> vlan id for MLAG traffic
            trunk_group_name ( str )
        """
        mlag_svi_address_range = mlag_svi_address_range
        mlag_config = ""
        mlag_general_section = ""
        mlag_vlan_section = ""
        mlag_interface_section = ""
        mlag_mlag_section = ""

        mlag_mlag_section += "ip virtual-router mac-address {}\n".format(virtual_mac)
        mlag_mlag_section += "!\n"

        hosts = list(ipaddress.ip_network(mlag_svi_address_range).hosts())
        if len(hosts) < 2:
            assert "{}  is an invalid address range for SVI".format(mlag_svi_address_range)
        if role == "primary":
            svi_address = hosts[0]
            peer_address = hosts[1]
        else:
            svi_address = hosts[1]
            peer_address = hosts[0]
        #Get interfaces
        if interfaces is None:
            assert "Interfaces is None. Please specify interfaces"
            return

        #Configure MLAG vlan
        mlag_vlan_section += "vlan {}\n".format(vlan)
        mlag_vlan_section += "   name MLAG-Peer-Vlan\n"
        mlag_vlan_section += "   trunk group {}\n".format(trunk_group_name)
        mlag_vlan_section += "!\n"

        mlag_vlan_section += "interface Vxlan1\n"
        mlag_vlan_section += "   vxlan virtual-router encapsulation mac-address mlag-system-id\n"
        mlag_vlan_section += "!\n"

        #Disable spanning tree on MLAG vlan
        mlag_general_section += "no spanning-tree vlan-id {}\n".format(vlan)
        mlag_general_section += "!\n"
        mlag_general_section += "spanning-tree mode {}\n".format(stp_mode)

        #Configure physical interface configs
        for interface in interfaces:
            mlag_interface_section += "interface {}\n".format(interface)
            mlag_interface_section += "   description MLAG Interface\n"
            mlag_interface_section += "   switchport mode trunk\n"
            mlag_interface_section += "   mtu {}\n".format(9214)
            mlag_interface_section += "   channel-group {} mode active\n".format(port_channel)
            mlag_interface_section += "   logging event link-status\n"
            mlag_interface_section += "   logging event congestion-drops\n"
            mlag_interface_section += "!\n"

        #Configure port channel
        mlag_interface_section += "interface Port-Channel{}\n".format(port_channel)
        mlag_interface_section += "   description MLAG Peer Port-Channel\n"
        mlag_interface_section += "   load-interval {}\n".format(5)
        mlag_interface_section += "   switchport mode trunk\n"
        mlag_interface_section += "   switchport trunk group {}\n".format(trunk_group_name)
        mlag_interface_section += "!\n"

        #Configure SVI
        mlag_interface_section += "interface Vlan{}\n".format(vlan)
        mlag_interface_section += "   description MLAG peer link\n"
        mlag_interface_section += "   mtu {}\n".format(9214)
        mlag_interface_section += "   no autostate\n"
        mlag_interface_section += "   ip address {}/{}\n".format(svi_address, ipaddress.ip_network(mlag_svi_address_range).prefixlen)
        mlag_interface_section += "!\n"

        #Configure mlag

        reload_delay = (300, 360)
        try:
            if switch_helpers.check_if_model_uses_chip_in_sand_family(self.model) == True:
                reload_delay = ("780","1020")
        except KeyError as e:
            print("Could not identify chip family for {}\nCheck to see that proper mlag reload delays are applied.".format(self.hostname))
            print(e)

        mlag_mlag_section += "mlag\n"
        mlag_mlag_section += "   domain-id {}\n".format(mlag_domain_id)
        mlag_mlag_section += "   local-interface vlan {}\n".format(vlan)
        mlag_mlag_section += "   peer-address {}\n".format(peer_address)
        if heartbeat_address is not None:
            if heartbeat_vrf is None:
                mlag_mlag_section += "   peer-address heartbeat {}\n".format(heartbeat_address)
            else:
                mlag_mlag_section += "   peer-address heartbeat {} vrf {}\n".format(heartbeat_address, heartbeat_vrf)
        mlag_mlag_section += "   peer-link port-channel {}\n".format(port_channel)
        mlag_mlag_section += "   reload-delay mlag {}\n".format(reload_delay[0])
        mlag_mlag_section += "   reload-delay non-mlag {}\n".format(reload_delay[1])
        if dual_primary_detection_action is not None:
            mlag_mlag_section += "   dual-primary detection delay {} action {}\n".format(dual_primary_detection_delay, dual_primary_detection_action)
        mlag_mlag_section += "!\n"

        mlag_interface_section = switch_helpers.sortInterfaceConfig(mlag_interface_section)

        mlag_elements = [mlag_general_section, mlag_vlan_section, mlag_interface_section,
                        mlag_mlag_section]

        return "".join(mlag_elements)

    def build_ip_interface_underlay(self, interfaces_to_ips=None, mtu_size=1500):
        """
        Args:
            interfaces_to_ips ({str: {str: str}}) ->  key is the interface, value is another dict of format
                                             {"IP Address": "1.1.1.1/31",
                                             "Remote Hostname": "example host",
                                             "Remote Interface": "Ethernet1"}
            mlag_enabled ( bool ) -> Used to determine if mlag is enabled
            virtual_mac ( str ) -> virtual mac used for mlag switches to receive traffic
        """
        if interfaces_to_ips is None:
            assert "Need interface to ip dictionary"
            return

        #build config
        ip_interface_config = []

        #Sort interfaces
        interfaces_to_ips = OrderedDict(sorted(interfaces_to_ips.items()))

        for interface, interface_info in interfaces_to_ips.items():
            ip_interface_config.append("interface {}".format(interface))
            ip_interface_config.append("   description {}".format("Connection to {} - {}".format(interface_info["Remote Hostname"], interface_info["Remote Interface"])))
            ip_interface_config.append("   mtu {}".format(mtu_size))
            ip_interface_config.append("   no switchport")
            ip_interface_config.append("   ip address {}".format(interface_info["IP Address"]))
            ip_interface_config.append("   logging event link-status")
            ip_interface_config.append("   logging event congestion-drops")
            ip_interface_config.append("!")   



        ip_interface_config = switch_helpers.sortInterfaceConfig("\n".join(ip_interface_config))
        return ip_interface_config

    def build_leaf_bgp(self, asn, protocol, underlay_source_address, remote_ases_and_neighbors,
                    underlay_source_interface="Loopback0",
                    router_id=None, peer_group_name=None, mlag_peer_group_name="MLAG-IPv4-UNDERLAY-PEER",
                    update_wait_install=True, underlay_pwd_hash=None, overlay_pwd_hash=None, max_routes=0, bfd=True, vrfs=None, role=None,
                    mlag_peer_link=None, route_map=None, prefix_lists=None):
        """
        Args
            asn ( int ) --> asn number
            role ( str ) --> "leaf" or "spine"
            underlay_source_address (str)  --> address of loopback 0 in CIDR notation; i.e. "1.1.1.1/32"
            number of neighbors ( int ) -->  number of neighbors to peer with
            mlag_enabled ( bool ) --> flag to signal if mlag is enabled (should we set a virtual-router mac-address)
            remote_ases_and_neighbors ( {int: [str]} ) --> dictionary where keys are keys are remote ases and values are neighbors that will belong to those ases.
                                                            Example: {65000:["172.16.200.1","172.16.200.3"]}
            route_map ( {str:[{str:str}]} ) --> Route map info i.e. {"route-map1": [{"permit 10", "match ip address prefix-list PL-Loopbacks"},
                                                                                    {"permit 20", "match ip address prefix-list PL-P2P-Underlay"}]}
            prefix_lists ( [{str : [str]}] ) --> List of prefix lists [{"pl1": ["statement 1", "statement 2"]}, {"pl2":["statement 1"]}]
        """
        #Calculate number of neighbors
        number_of_neighbors = 0
        for bgp_asn, neighbors in remote_ases_and_neighbors.items():
            number_of_neighbors += len(neighbors)

        bgp_underlay_config = []

        bgp_underlay_config.append("interface {}".format(underlay_source_interface))
        bgp_underlay_config.append("   description EVPN Peering Source")
        bgp_underlay_config.append("   ip address {}".format(underlay_source_address))
        bgp_underlay_config.append("!")

        bgp_underlay_config.append("ip routing")
        bgp_underlay_config.append("!")
        bgp_underlay_config.append("service routing protocols model multi-agent")
        bgp_underlay_config.append("!")

        router_id = underlay_source_address.split("/")[0] if router_id is None else router_id

        #Build bgp config
        if protocol == "ipv4":
            if route_map is not None and prefix_lists is not None:
                for prefix_list_dict in prefix_lists:
                    for prefix_list_name, prefix_list_statements in prefix_list_dict.items():
                        for statement in prefix_list_statements:
                            bgp_underlay_config.append("ip prefix-list {} {}".format(prefix_list_name, statement))
                bgp_underlay_config.append("!")
                for route_map_name, statements in route_map.items():
                    for statement_info in statements:
                        for seq, match in statement_info.items():
                            bgp_underlay_config.append("route-map  {} {}".format(route_map_name, seq))
                            bgp_underlay_config.append("   {}".format(match))
                            bgp_underlay_config.append("!")

            peer_group_name = peer_group_name if peer_group_name is not None else "IPv4_UNDERLAY_PEERS"
            bgp_underlay_config.append("router bgp {}".format(asn))
            bgp_underlay_config.append("   router-id {}".format(router_id))
            bgp_underlay_config.append("   no bgp default ipv4-unicast")
            if number_of_neighbors is not None:
                bgp_underlay_config.append("   maximum-paths {} ecmp {}".format(number_of_neighbors, number_of_neighbors))
            bgp_underlay_config.append("   neighbor {} peer group".format(peer_group_name))
            if bfd == True:
                bgp_underlay_config.append("   neighbor {} bfd".format(peer_group_name))
            if underlay_pwd_hash is not None:
                bgp_underlay_config.append("   neighbor {} password 7 {}".format(peer_group_name, underlay_pwd_hash))
            bgp_underlay_config.append("   neighbor {} send-community".format(peer_group_name))
            bgp_underlay_config.append("   neighbor {} maximum-routes {}".format(peer_group_name, max_routes))
            for remote_as, bgp_neighbors in remote_ases_and_neighbors.items():
                for neighbor in bgp_neighbors:
                    bgp_underlay_config.append("   neighbor {} peer group {}".format(neighbor, peer_group_name))
            if len(remote_ases_and_neighbors) == 1:
                bgp_underlay_config.insert(-(number_of_neighbors), "   neighbor {} remote-as {}".format(peer_group_name, next(iter(remote_ases_and_neighbors))))
            else:
                for remote_as, bgp_neighbors in remote_ases_and_neighbors.items():
                    for neighbor in bgp_neighbors:
                        bgp_underlay_config.append("   neighbor {} remote-as {}".format(neighbor, remote_as))

            if route_map is not None and prefix_lists is not None:
                bgp_underlay_config.append("   redistribute connected route-map {}".format(next(iter(route_map))))
            else:
                bgp_underlay_config.append("   redistribute connected")
            
            bgp_underlay_config.append("   !")
            bgp_underlay_config.append("   address-family ipv4")
            bgp_underlay_config.append("      neighbor {} activate".format(peer_group_name))
            bgp_underlay_config.append("!")

        if protocol == "evpn":
            vlan_section = ""
            vrf_section = ""
            interface_section = ""
            port_channel_section = ""
            vxlan_interface_section = ""
            ibgp_section = ""
            nat_config = ""
            peer_group_name = peer_group_name if peer_group_name is not None else "EVPN_OVERLAY_PEERS"
            bgp_underlay_config.append("router bgp {}".format(asn))
            bgp_underlay_config.append("   router-id {}".format(router_id))
            if number_of_neighbors is not None:
                bgp_underlay_config.append("   maximum-paths {} ecmp {}".format(number_of_neighbors, number_of_neighbors))
            bgp_underlay_config.append("   neighbor {} peer group".format(peer_group_name))
            bgp_underlay_config.append("   neighbor {} update-source {}".format(peer_group_name, underlay_source_interface))
            bgp_underlay_config.append("   neighbor {} ebgp-multihop 3".format(peer_group_name))
            if bfd == True:
                bgp_underlay_config.append("   neighbor {} bfd".format(peer_group_name))
            if overlay_pwd_hash is not None:
                bgp_underlay_config.append("   neighbor {} password 7 {}".format(peer_group_name, overlay_pwd_hash))
            bgp_underlay_config.append("   neighbor {} send-community".format(peer_group_name))
            bgp_underlay_config.append("   neighbor {} maximum-routes {}".format(peer_group_name, max_routes))
            for remote_as, bgp_neighbors in remote_ases_and_neighbors.items():
                for neighbor in bgp_neighbors:
                    bgp_underlay_config.append("   neighbor {} peer group {}".format(neighbor, peer_group_name))
            if len(remote_ases_and_neighbors) == 1:
                bgp_underlay_config.insert(-(number_of_neighbors), "   neighbor {} remote-as {}".format(peer_group_name, next(iter(remote_ases_and_neighbors))))
            else:
                for remote_as, bgp_neighbors in remote_ases_and_neighbors.items():
                    for neighbor in bgp_neighbors:
                        bgp_underlay_config.append("   neighbor {} remote-as {}".format(neighbor, remote_as))
            # bgp_underlay_config.append("   redistribute connected")
            bgp_underlay_config.append("   !")
            bgp_underlay_config.append("   address-family evpn")
            bgp_underlay_config.append("      neighbor {} activate".format(peer_group_name))
            bgp_underlay_config.append("!")
            
            if vrfs is not None:
                vxlan_interface_section += "interface Vxlan1\n"

                for vrf, vrf_info in vrfs.items():
                    ibgp_address_range = vrf_info["SVI Address Range"]
                    hosts = list(ipaddress.ip_network(ibgp_address_range).hosts())
                    if role != "secondary":
                        ibgp_svi_address = hosts[0]
                        ibgp_neighbor_address = hosts[1]
                    else:
                        ibgp_svi_address = hosts[1]
                        ibgp_neighbor_address = hosts[0]

                    route_distinguisher = vrf_info["Route Distinguisher"]
                    route_target = vrf_info["Route Target"]
                    vlan = vrf_info["Vlan"]
                    vni = vrf_info["VNI"]
                    nat_ip_address = vrf_info["NAT IP Address"]
                    nat_interface = vrf_info["NAT Interface"].strip() if vrf_info["NAT Interface"].strip() != "" else None
                    vrf_section += "vrf instance {}\n".format(vrf)
                    vrf_section += "!\n"
                    vrf_section += "ip routing vrf {}\n".format(vrf)
                    vrf_section += "!\n"

                    if role is not None:
                        vlan_section += "vlan {}\n".format(vlan)
                        vlan_section += "   name {}_IBGP_PEER\n".format(vrf)
                        vlan_section += "   trunk group {}_IBGP_PEER\n".format(vrf)
                        vlan_section += "!\n"

                    
                        interface_section += "interface Vlan{}\n".format(vlan)
                        interface_section += "   description {}_IBGP_PEER\n".format(vrf)
                        interface_section += "   vrf {}\n".format(vrf)
                        interface_section += "   mtu {}\n".format(9214)
                        interface_section += "   ip address {}/{}\n".format(ibgp_svi_address,ipaddress.ip_network(ibgp_address_range).prefixlen)
                        interface_section += "!\n"


                        if "interface Port-Channel{}\n".format(mlag_peer_link) not in port_channel_section:
                            port_channel_section += "interface Port-Channel{}\n".format(mlag_peer_link)
                        port_channel_section += "   switchport trunk group {}_IBGP_PEER\n".format(vrf)
        

                    ibgp_section += "   vrf {}\n".format(vrf)
                    ibgp_section += "      router-id {}\n".format(router_id)
                    ibgp_section += "      rd {}\n".format(route_distinguisher)
                    ibgp_section += "      route-target import evpn {}\n".format(route_target)
                    ibgp_section += "      route-target export evpn {}\n".format(route_target)
                    # ibgp_section += "      bgp default ipv4-unicast\n"
                    if role is not None:
                        ibgp_section += "      neighbor {} peer group {}\n".format(ibgp_neighbor_address, mlag_peer_group_name)
                        ibgp_section += "      neighbor {} update-source Vlan{}\n".format(ibgp_neighbor_address, vlan)
                    ibgp_section += "      redistribute connected\n"
                    ibgp_section += "!\n"
                    vxlan_interface_section += "   vxlan vrf {} vni {}\n".format(vrf, vni)

                    if nat_ip_address is not None and nat_interface is not None:
                        interface_section += "interface {}\n".format(nat_interface)
                        interface_section += "   vrf {}\n".format(vrf)
                        interface_section += "   ip address {}\n".format(nat_ip_address)
                        interface_section += "!\n"
                        nat_config += "ip address virtual source-nat vrf {} address {}\n!\n".format(vrf, nat_ip_address)

                vxlan_interface_section += "\n!"
                port_channel_section += "\n!"
                interface_section = switch_helpers.sortInterfaceConfig(interface_section + vxlan_interface_section + port_channel_section)


                bgp_underlay_config.insert(0, nat_config)    
                bgp_underlay_config.insert(0, interface_section)
                bgp_underlay_config.insert(0, vrf_section)
                bgp_underlay_config.insert(0, vlan_section)
                bgp_underlay_config.append(ibgp_section)


        return "\n".join(bgp_underlay_config)

    def build_dynamic_spine_bgp(self, asn, protocol, number_of_neighbors, underlay_source_address,
                            asn_range, address_range, 
                            prefix_lists=None, route_map=None,
                            underlay_source_interface="Loopback0",
                            router_id=None, peer_group_name=None, peer_filter_name="LEAF-AS-RANGE",
                            update_wait_install=True, underlay_pwd_hash=None, overlay_pwd_hash=None, max_routes=0, bfd=True):
        '''
        role = "leaf" or "spine"
        network_plane = "ipv4" or "evpn"
        pwd_hash ( str )
        prefix_lists ( [ {"name": ["statement1", "statement2"]}, ... ] )
        route_maps ( [ {"name": ["statement1", "statement2"]}, ... ] )
        '''
        bgp_underlay_config = []

        router_id = underlay_source_address.split("/")[0] if router_id is None else router_id

        if protocol == "ipv4":
            peer_group_name = peer_group_name if peer_group_name is not None else "IPv4-UNDERLAY-PEERS"

            bgp_underlay_config.append("interface {}".format(underlay_source_interface))
            bgp_underlay_config.append("   ip address {}".format(underlay_source_address))
            bgp_underlay_config.append("!")
            bgp_underlay_config.append("ip routing")
            bgp_underlay_config.append("!")
            bgp_underlay_config.append("service routing protocols model multi-agent")
            bgp_underlay_config.append("!")

            bgp_underlay_config.append("peer-filter {}".format(peer_filter_name))
            bgp_underlay_config.append("   10 match as-range {} result accept".format(asn_range))
            bgp_underlay_config.append("!")

            if route_map is not None and prefix_lists is not None:
                for prefix_list_dict in prefix_lists:
                    for prefix_list_name, prefix_list_statements in prefix_list_dict.items():
                        for statement in prefix_list_statements:
                            bgp_underlay_config.append("ip prefix-list {} {}".format(prefix_list_name, statement))
                bgp_underlay_config.append("!")
                for route_map_name, statements in route_map.items():
                    for statement_info in statements:
                        for seq, match in statement_info.items():
                            bgp_underlay_config.append("route-map  {} {}".format(route_map_name, seq))
                            bgp_underlay_config.append("   {}".format(match))
                            bgp_underlay_config.append("!")

            bgp_underlay_config.append("router bgp {}".format(asn))
            bgp_underlay_config.append("   router-id {}".format(router_id))
            if number_of_neighbors is not None:
                bgp_underlay_config.append("   maximum-paths {} ecmp {}".format(number_of_neighbors, number_of_neighbors))
            if update_wait_install == True:
                bgp_underlay_config.append("   update wait-install")
            bgp_underlay_config.append("   no bgp default ipv4-unicast")
            bgp_underlay_config.append("   bgp listen range {} peer-group {} peer-filter {}".format(address_range, peer_group_name, peer_filter_name))
            bgp_underlay_config.append("   neighbor {} peer group".format(peer_group_name))
            bgp_underlay_config.append("   neighbor {} send-community".format(peer_group_name))
            if bfd == True:
                bgp_underlay_config.append("   neighbor {} bfd".format(peer_group_name))
            if underlay_pwd_hash is not None:
                bgp_underlay_config.append("   neighbor {} password 7 {}".format(peer_group_name, underlay_pwd_hash))
            bgp_underlay_config.append("   neighbor {} maximum-routes {}".format(peer_group_name, max_routes))
            if route_map is not None and prefix_lists is not None:
                bgp_underlay_config.append("   redistribute connected route-map {}".format(next(iter(route_map))))
            else:
                bgp_underlay_config.append("   redistribute connected")
            bgp_underlay_config.append("   !")
            bgp_underlay_config.append("   address-family ipv4")
            bgp_underlay_config.append("      neighbor {} activate".format(peer_group_name))
            bgp_underlay_config.append("!")

        elif protocol == "evpn":
            peer_group_name = peer_group_name if peer_group_name is not None else "EVPN-OVERLAY-PEERS"

            bgp_underlay_config.append("interface {}".format(underlay_source_interface))
            bgp_underlay_config.append("   description EVPN PEERING SOURCE")
            bgp_underlay_config.append("!")

            bgp_underlay_config.append("peer-filter {}".format(peer_filter_name))
            bgp_underlay_config.append("   10 match as-range {} result accept".format(asn_range))
            bgp_underlay_config.append("!")

            bgp_underlay_config.append("router bgp {}".format(asn))
            bgp_underlay_config.append("   router-id {}".format(router_id))
            if number_of_neighbors is not None:
                bgp_underlay_config.append("   maximum-paths {} ecmp {}".format(number_of_neighbors, number_of_neighbors))
            bgp_underlay_config.append("   bgp listen range {} peer-group {} peer-filter {}".format(address_range, peer_group_name, peer_filter_name))
            bgp_underlay_config.append("   neighbor {} peer group".format(peer_group_name))
            bgp_underlay_config.append("   neighbor {} next-hop-unchanged".format(peer_group_name))
            bgp_underlay_config.append("   neighbor {} update-source {}".format(peer_group_name, underlay_source_interface))
            bgp_underlay_config.append("   neighbor {} ebgp-multihop 3".format(peer_group_name))
            if bfd == True:
                bgp_underlay_config.append("   neighbor {} bfd".format(peer_group_name))
            if overlay_pwd_hash is not None:
                bgp_underlay_config.append("   neighbor {} password 7 {}".format(peer_group_name, overlay_pwd_hash))
            bgp_underlay_config.append("   neighbor {} send-community".format(peer_group_name))
            bgp_underlay_config.append("   neighbor {} maximum-routes {}".format(peer_group_name, max_routes))
            bgp_underlay_config.append("   !")
            bgp_underlay_config.append("   address-family evpn")
            bgp_underlay_config.append("      neighbor {} activate".format(peer_group_name))
            bgp_underlay_config.append("!")
        return "\n".join(bgp_underlay_config)
        

    def build_ibgp_between_mlag(self, role, asn, router_id, mlag_peer_link, ibgp_address_range="172.21.16.254/31", svi=4094,
                                peer_group_name="MLAG-IPv4-UNDERLAY-PEER", ibgp_pwd_hash=None, max_routes=12000):
        ibgp_address_range = ibgp_address_range
        ibgp_section = ""

        hosts = list(ipaddress.ip_network(ibgp_address_range).hosts())
        if role == "primary":
            ibgp_svi_address = hosts[0]
            ibgp_neighbor_address = hosts[1]
        else:
            ibgp_svi_address = hosts[1]
            ibgp_neighbor_address = hosts[0]

         
        ibgp_section += "vlan {}\n".format(svi)
        ibgp_section += "   name MLAG_IBGP_Peering\n"
        ibgp_section += "   trunk group IBGP-PEER\n"
        ibgp_section += "!\n"

        ibgp_section += "interface Vlan{}\n".format(svi)
        ibgp_section += "   description MLAG IBGP Peering\n"
        ibgp_section += "   mtu {}\n".format(9214)
        ibgp_section += "   ip address {}/{}\n".format(ibgp_svi_address, ipaddress.ip_network(ibgp_address_range).prefixlen)
        ibgp_section += "!\n"


        ibgp_section += "interface Port-Channel{}\n".format(mlag_peer_link)
        ibgp_section += "   switchport trunk group IBGP-PEER\n"
        ibgp_section += "!\n"


        ibgp_section += "router bgp {}\n".format(asn)
        ibgp_section += "   router-id {}\n".format(router_id)
        ibgp_section += "   neighbor {} peer group\n".format(peer_group_name)
        ibgp_section += "   neighbor {} remote-as {}\n".format(peer_group_name, asn)
        ibgp_section += "   neighbor {} next-hop-self\n".format(peer_group_name)
        if ibgp_pwd_hash is not None:
            ibgp_section += "   neighbor {} password 7 {}\n".format(peer_group_name, ibgp_pwd_hash)
        ibgp_section += "   neighbor {} send-community\n".format(peer_group_name)
        ibgp_section += "   neighbor {} maximum-routes {}\n".format(peer_group_name, max_routes)
        ibgp_section += "   neighbor {} peer group {}\n".format(ibgp_neighbor_address, peer_group_name)
        ibgp_section += "   !\n"
        ibgp_section += "   address-family ipv4\n"
        ibgp_section += "      neighbor {} activate\n".format(peer_group_name)
        ibgp_section += "!\n"
           
        return ibgp_section

        
    def build_vxlan_data_plane(self, overlay_source__address, port=4789, overlay_source_interface="Loopback1"):        
        """Creates a Vxlan data plane configuration from the given inputs
        
        Arguments:
            vlans_to_vnis {{int:int}} -- dictionary of vlan to vni mappings, vlan is key vni is value
            overlay_source__address {str} -- IP address of the overlay source address. Format 1.1.1.1/32
        
        Keyword Arguments:
            port {int} -- port number for vxlan to run on (default: {4789})
            overlay_source_interface {str} -- name of source interface (default: "Loopback1")
        
        Returns:
            str -- Vxlan data plane configuration
        """
        vxlan_config = []

        #build vxlan config
        vxlan_config.append("interface {}".format(overlay_source_interface))
        vxlan_config.append("   description VXLAN Tunnel Source")
        vxlan_config.append("   ip address {}".format(overlay_source__address))
        vxlan_config.append("!")

        try:
            if switch_helpers.check_if_model_uses_chip_in_sand_family(self.model) == True:
                vxlan_config.append("hardware tcam")
                vxlan_config.append("system profile vxlan-routing")
                vxlan_config.append("!")
        except KeyError as e:
            print("Could not identify chip family for {}\nMake sure 'hardware tcam' and 'system profile vxlan-routing' are NOT necessary for this platform".format(self.hostname))
            print(e)

        vxlan_config.append("interface Vxlan1")
        vxlan_config.append("   vxlan source-interface {}".format(overlay_source_interface))
        vxlan_config.append("   vxlan udp-port {}".format(port))

        return "\n".join(vxlan_config)

    def build_vxlan_control_plane(self, control_plane, vtep_peers=None, cvx_addresses=None, evpn_peers=None,
                                    asn=None, source_interface="Loopback 0", role=None, evpn_model="symmetric",
                                    vrf="vrf1", vrf_vni=1, vrf_route_distinguisher=None, vrf_route_target="1001",
                                    virtual_address_mode="ip address virtual", underlay_source_address=None, peer_group_name=None):
        """
        Args:
            control_plane ( str ) --> type of control plane option; options are "her", "cvx", and "evpn"
            vtep peers ( [str] ) --> List of IP addresses
            cvx_addresses ( [str] ) --> List of IP addresses of CVX in CIDR
            evpn_peers ( {str:str} ) --> dictionary of remote-ases and bgp neighbors
            asn ( int ) --> bgp asn for switch
        """
        #build vxlan_control_plane confif
        config = []
        if control_plane == "her":
            if vtep_peers is None:
                assert "Error: Head End Replication chosen as control plane and no vtep_peers provided."
            config.append("interface Vxlan1")
            for vtep in vtep_peers:
                config.append("   vxlan flood vtep {}".format(vtep))
            config.append("!")

    def build_her_vxlan_control_plane(self, vtep_peers):
            config = []
            config.append("interface Vxlan1")
            for vtep in vtep_peers:
                config.append("   vxlan flood vtep add {}".format(vtep))
            config.append("!")
            
            return "\n".join(config)

    def build_evpn_vxlan_control_plane(self, role, asn, protocol, underlay_source_address, evpn_neighbors,
                        underlay_source_interface="Loopback0", router_id=None, peer_group_name=None, pwd=None,
                        max_routes=0, bfd=True, vrfs=None, number_of_neighbors=None, asn_range=None, address_range=None,
                        prefix_lists=None, rt_maps=None, peer_filter_name="LEAF-AS-RANGE"
                        ):
        if role == "leaf":
            config = self.build_leaf_bgp(asn, "evpn", underlay_source_address, evpn_neighbors,
                                    underlay_source_interface=underlay_source_interface,
                                    router_id=router_id, peer_group_name=peer_group_name,
                                    pwd=pwd, max_routes=max_routes, bfd=bfd, vrfs=vrfs)
        elif role == "spine":
            config = self.build_dynamic_spine_bgp(asn, "evpn", number_of_neighbors, asn_range, address_range,
                                prefix_lists=prefix_lists, route_maps=rt_maps, underlay_source_interface=underlay_source_interface,
                                router_id=router_id, peer_group_name=peer_group_name, peer_filter_name=peer_filter_name,
                                pwd=pwd, max_routes=max_routes, bfd=bfd)
        return config


    def build_evpn(self, evpn_peers, asn=None, source_interface="loopback 0", role=None, evpn_model=None,
                     vrf="vrf1", vrf_vni=1, vrf_route_distinguisher="1.1.1.1", vrf_route_target="1001",
                     virtual_address_mode="ip address virtual"):
        """
        Args:
            evpn_peers ( {str:str} ) --> dictionary of remote-ases and bgp neighbors
            asn ( int ) --> bgp asn for switch
        """
        

        vxlan_config = []
        vrf_config = []
        interface_config = []
        bgp_config = []


        if evpn_peers is None or asn is None:
            assert "Error: EVPN chosen as control plane and either no evpn peers provided or no BGP asn provided"
            return

        if role=="leaf":
            peer_group = "SPINE-EVPN-TRANSIT"
        elif role == "spine":
            peer_group = "VTEP-EVPN-TRANSIT"
        else:
            assert "Error: No role specified. Please specify either 'spine' or 'leaf'"
            return

        #calculate number of neighbors
        number_of_neighbors = 0
        for bgp_asn, neighbors in evpn_peers.items():
            number_of_neighbors += len(neighbors)

        bgp_config.append("router bgp {}".format(asn))
        bgp_config.append("   neighbor {} peer group".format(peer_group))
        bgp_config.append("   neighbor {} next-hop-unchanged".format(peer_group))
        bgp_config.append("   neighbor {} update-source {}".format(peer_group, source_interface))
        bgp_config.append("   neighbor {} ebgp-multihop".format(peer_group))
        bgp_config.append("   neighbor {} send-community extended".format(peer_group))
        bgp_config.append("   neighbor {} maximum-routes 0".format(peer_group))

        for remote_as, bgp_neighbors in evpn_peers.items():
            for neighbor in bgp_neighbors:
                bgp_config.append("   neighbor {} peer group {}".format(neighbor, peer_group))
        if len(evpn_peers) == 1 and role == "leaf":
            bgp_config.insert(-(number_of_neighbors), "   neighbor {} remote-as {}".format(peer_group, next(iter(evpn_peers))))
        else:
            for remote_as, bgp_neighbors in evpn_peers.items():
                for neighbor in bgp_neighbors:
                    bgp_config.append("   neighbor {} remote-as {}".format(neighbor, remote_as))
        bgp_config.append("   !")
        bgp_config.append("   address-family evpn")
        bgp_config.append("      neighbor {} activate".format(peer_group))
        bgp_config.append("   !")
        bgp_config.append("   address-family ipv4")
        bgp_config.append("      no neighbor {} activate".format(peer_group))
        bgp_config.append("   !")

        if role == "leaf":
            if evpn_model == "symmetric":
                vxlan_config.append("interface Vxlan1")
                vxlan_config.append("   vxlan vrf {} vni {}".format(vrf, vrf_vni))

                vrf_config.append("vrf instance {}".format(vrf))
                vrf_config.append("!")
                bgp_config.append("   vrf {}".format(vrf))
                bgp_config.append("      rd {}".format(vrf_route_distinguisher))
                bgp_config.append("      route-target import {}".format(vrf_route_target))
                bgp_config.append("      route-target export {}".format(vrf_route_target))
                bgp_config.append("      redistribute connected")
                bgp_config.append("      redistribute static")
                bgp_config.append("   !")

            else:
                assert "Error: Invalid evpn model.  Options are 'central', 'symmetric', and 'asymmetric'"



        evpn_config = ["\n".join(vxlan_config), "\n".join(vrf_config), "\n".join(interface_config), "\n".join(bgp_config)]

        evpn_config = ["\n".join(evpn_config)]

        return evpn_config

    
    def build_cvx_vxlan_control_plane(self, cvx_addresses, source_interface="Loopback0"):
        """Creates a CVX control plane config
        
        Arguments:
            cvx_address [{str}] -- list of IP address of the CVX hosts
        
        Returns:
            [list(str)] -- Returns a list where the lone element is the necessary CVX vxlan data plane configuration 
        """
        config = []
        if cvx_addresses is None:
            assert "Error: CVX chosen as control plane and no CVX address provided"
            return
        config.append("management cvx")
        for cvx_address in cvx_addresses:
            config.append("  server host {}".format(cvx_address.split("/")[0]))
        config.append("  source-interface {}".format(source_interface))
        config.append("  no shutdown")
        config.append("!")
        config.append("interface Vxlan1")
        config.append("  vxlan controller-client")
        config.append("!")

        return "\n".join(config)

    def build_cvx_control_plane(self):
        '''
        Generates the configuration to turn on the vxlan control plane feature for a cvx controller
        '''
        config = '''cvx
  no shutdown
  service vxlan
    no shutdown'''
        return config
        
    def add_vlans(self, vlan_info, vxlan=True, evpn=False, evpn_model=None, asn=None,
                    virtual_address_mode="ip address virtual", mtu=9214):
        """
            asn ( int ) --> bgp asn for switch
            svi_to_address ( {int:{str:str}}) --> dictionary of vlans to vlan info virtual ip addresses
                                                i.e. {2: {"SVI Address": "172.16.2.1/24", "Name":"Accounting", "VNI": 20}}

            virtual_address_mode ( str ) --> signals to use 'ip address virtual' or 'ip virtual-router address' for svi vIP
        """
        vlan_config = ""
        interface_config = ""
        bgp_config = ""
        vxlan_config = ""
        if vxlan == True:
            vxlan_config += "interface Vxlan1\n"

        if evpn == True:
            bgp_config += "router bgp {}\n".format(asn)
            # bgp_config += "  router-id {}\n".format(source_interface)
            # bgp_config += "!\n"
        #Order SVIs
        vlan_info = OrderedDict(sorted(vlan_info.items()))
        # print(json.dumps(vlan_info, indent=2))
        for vlan, info in vlan_info.items():
            vlan_config += "vlan {}\n".format(vlan)
            if info["Name"] is None or info["Name"] != "":
                vlan_config += "   name {}\n".format(info["Name"])
            vlan_config += "!\n"

            if vxlan == True and info["Stretched"] == True:
                vxlan_config += "   vxlan vlan {} vni {}\n".format(vlan, info["VNI"])
            
            if info["SVI Address"] is not None and info["SVI Address"].strip() != "":
                interface_config += "interface Vlan{}\n".format(vlan)
                interface_config += "   mtu {}\n".format(mtu)
                if evpn==True and evpn_model == "symmetric":
                    interface_config += "   vrf {}\n".format(info["Vrf"])
                if virtual_address_mode == "ip address virtual":
                    interface_config += "   ip address virtual {}\n".format(info["SVI Address"])
                    if info["SVI Address Secondary"] != "":
                        interface_config += "   ip address virtual {} secondary\n".format(info["SVI Address Secondary"])
                elif virtual_address_mode == "ip virtual-router address":
                    interface_config += "   ip virtual-router address {}\n".format(info["SVI Address"].split("/")[0])
                if info["DHCP Helper Addresses"][0] != "" and info["DHCP Helper Interface"] is not None:
                    for address in info["DHCP Helper Addresses"]:
                        interface_config += "   ip helper-address {} source-interface {}\n".format(address, info["DHCP Helper Interface"])

                interface_config += "   arp aging timeout 1500\n"
                if info["Enabled"] == True:
                    interface_config += "   no shutdown\n"
                else:
                    interface_config += "   shutdown\n"
                interface_config += "!\n"
                
            if evpn == True:
                bgp_config += "  vlan {}\n".format(vlan)
                bgp_config += "     rd {}\n".format(info["Route Distinguisher"])
                bgp_config += "     route-target both {}:{}\n".format(info["VNI"], info["VNI"])
                bgp_config += "     redistribute learned\n"
                bgp_config += "  !\n"

        return "\n".join([vlan_config, interface_config, vxlan_config, bgp_config])

    def build_nat_config(self, vrfs, nat_ip):
        interface_config = ""
        nat_details = ""
        for vrf, details in vrfs.items():
            if details["NAT Interface"].strip() == "":
                continue
            interface_config += "interface {}\n".format(details["NAT Interface"])
            interface_config += "   vrf {}\n".format(vrf)
            interface_config += "   ip address {}\n".format(nat_ip)
            interface_config += "!\n"
            nat_details += "ip address virtual source-nat vrf {} address {}\n".format(vrf, nat_ip)
        nat_config = interface_config + nat_details
        return nat_config

          
    def add_vrfs(self, asn, router_id, mlag_enabled=False, role=None, vrfs_info=None):
        '''
        Args:
            vrfs_info: includes VRF info
                dictionary:
                    {
                        "vrf_name":{
                            "Route Distinguisher": str,
                            "Route Target": int,
                            "Vlan": int,
                            "SVI Address Range": str,
                            "VNI": int
                        }
                    }
        '''
        vlan_section = ""
        vrf_section = ""
        interface_section = ""
        vxlan_interface_section = ""
        ibgp_section = ""

        #Start ibgp section
        ibgp_section += "router bgp {}\n".format(asn)
        ibgp_section += "   router-id {}\n".format(router_id)

        #Start interface section
        vxlan_interface_section += "interface Vxlan1\n"

        for vrf, vrf_info in vrfs_info.items():
            ibgp_address_range = vrf_info["SVI Address Range"]
            hosts = list(ipaddress.ip_network(ibgp_address_range).hosts())
            if role == "primary":
                ibgp_svi_address = hosts[0]
                ibgp_neighbor_address = hosts[1]
            else:
                ibgp_svi_address = hosts[1]
                ibgp_neighbor_address = hosts[0]

            route_distinguisher = vrf_info["Route Distinguisher"]
            route_target = vrf_info["Route Target"]
            vlan = vrf_info["Vlan"]
            vni = vrf_info["VNI"]

            vrf_section += "vrf instance {}\n".format(vrf)
            vrf_section += "!\n"
            vrf_section += "ip routing vrf {}\n".format(vrf)
            vrf_section += "!\n"
            vlan_section += "vlan {}\n".format(vlan)
            vlan_section += "   name {}_IBGP_PEER\n".format(vrf)
            vlan_section += "   trunk group {}_IBGP_PEER\n".format(vrf)
            vlan_section += "!\n"

            interface_section += "interface Vlan{}\n".format(vlan)
            interface_section += "   description {}_IBGP_PEER\n".format(vrf)
            interface_section += "   vrf {}\n".format(vrf)
            interface_section += "   mtu {}\n".format(9214)
            interface_section += "   ip address {}/{}\n".format(ibgp_svi_address,ipaddress.ip_network(ibgp_address_range).prefixlen)
            interface_section += "!\n"

            ibgp_section += "   vrf {}\n".format(vrf)
            ibgp_section += "      rd {}\n".format(route_distinguisher)
            ibgp_section += "      route-target import {}\n".format(route_target)
            ibgp_section += "      route-target export {}\n".format(route_target)
            ibgp_section += "      neighbor {} remote-as {}\n".format(ibgp_neighbor_address, asn)
            ibgp_section += "      neighbor {} next-hop-self\n".format(ibgp_neighbor_address)
            ibgp_section += "      neighbor {} update-source Vlan{}\n".format(ibgp_neighbor_address, vlan)
            ibgp_section += "      neighbor {} allowas-in 1\n".format(ibgp_neighbor_address)
            ibgp_section += "      neighbor {} maximum-routes 12000\n".format(ibgp_neighbor_address)
            ibgp_section += "      redistribute connected\n".format(ibgp_neighbor_address)
            ibgp_section += "!\n"

            vxlan_interface_section += "   vxlan vrf {} vni {}\n".format(vrf, vlan)
            
        interface_section = switch_helpers.sortInterfaceConfig(interface_section + vxlan_interface_section)

        return "".join([vlan_section, vrf_section, interface_section, ibgp_section])

    def order_interfaces_by_most_common_speed(self):
        """
        Returns a dictionary of interfaces ordered by most common interface speed.  
        Bandwidth values are the keys, lists of interface names are the values.
        """
        interface_speeds = {}
        ordered_interface_speeds = OrderedDict()

        for interface in self.interfaces:
#            print json.dumps(interface)
            if interface["bandwidth"] == "" and interface["hardware_type"] != "Ethernet":
                continue
            if interface["interface"] == "Management1":
                continue
            if interface["bandwidth"] in list(interface_speeds):
                interface_speeds[interface["bandwidth"]].append(interface["interface"])
            else:
                interface_speeds[interface["bandwidth"]] = [interface["interface"]]
        for k in sorted(interface_speeds, key=lambda k: len(interface_speeds[k]), reverse=True):
            ordered_interface_speeds[k] = interface_speeds[k]
        
        return ordered_interface_speeds

