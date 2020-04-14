#import built in python libraries
import ipaddress, re, json, sys, signal, os
import cherrypy
import xlrd, xlwt
import logging
logging.basicConfig(level=logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler = logging.FileHandler('FabricBuilder.log', mode='w+')
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(handler)

from collections import OrderedDict
from getpass import getpass
#Disables no certificate CVP warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from Switch import Switch
from cvprac.cvp_client import CvpClient
from cvprac.cvp_client_errors import CvpClientError
from OrchestratorHelpers.template_parsers import *
from OrchestratorHelpers.cvp_operations import *
from OrchestratorHelpers.configletModifiers import *
from OrchestratorHelpers.main_helpers import *

#import parellelism libraries
# from Queue import Queue
# from queue import Empty
# import threading

path   = os.path.abspath(os.path.dirname(__file__))
config = {
  'global' : {
    'server.socket_host' : '127.0.0.1',
    'server.socket_port' : 8080,
    'server.thread_pool' : 8
  },
  '/static' : {
    'tools.staticdir.on'  : True,
    'tools.staticdir.dir' : os.path.join(path, 'static'),
    'tools.expires.on'    : True,
    'tools.expires.secs'  : 1
  }
}

#For python 2 and 3 compatibility
try:
    input = raw_input
except NameError:
    pass

class Handler(object):
    @cherrypy.expose
    def index(self):
        f = open("index.html", "r")
        
        return f.read()
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def run(self):

        result = {"operation": "request", "result": "success"}
        
        input_json = cherrypy.request.json
        print(input_json)

        run_script(**input_json)
        return result
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def log(self):
        f = open("FabricBuilder.log")
        text = f.read()
        f.close()
        return json.dumps(text)

    @cherrypy.expose
    def readfile(self):
        with xlrd.open_workbook('workbook.xls') as f:
            
            
            
            toReturn = {}
            def format(v):
                if type(v) == float:
                    return {'type':'text','title':int(val), 'width':200 }
                else:
                    return {'type':'text','title':v, 'width':200 }
                
            

            for n in range(0, f.nsheets):
                _sheet=f.sheet_by_index(n)
                _sheet.cell_value(0,0)
                toReturn[_sheet.name] = {'data':[],'columns':[format(val) for val in _sheet.row_values(0)]}
                for row in range(1, _sheet.nrows):
                    row = _sheet.row_values(row)
                    toReturn[_sheet.name]['data'].append(row)
                
        return json.dumps(toReturn)
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def writefile(self):

        result = {"operation": "request", "result": "success"}
        wb = xlwt.Workbook()
        input_json = cherrypy.request.json
        for sheet in input_json:
            tab = sheet[0]
            data = sheet[1:]
            
            ws = wb.add_sheet(tab)
            for r, row in enumerate(data):
                for c, v in enumerate(row):
                    ws.write(r,c,v)
        
        wb.save('workbook.xls')
        # Responses are serialized to JSON (because of the json_out decorator)
        return result
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def upload(self, myFile):

        result = {"operation": "request", "result": "success"}

        size = 0
        f = open("workbook.xls", "wb")
        
        
        while True:
            data = myFile.file.read(8192)
            f.write(data)
            if not data:
                f.close()
                break

        # Responses are serialized to JSON (because of the json_out decorator)
        return result


username = None
password = None
cvp = None
global_options = None
execute_tasks = False
telemetry_statement = None

#list of vtep peers in the event that static HER is the vxlan control plane
vtep_peers = []

#########################################################################################################

def deployL3LSLeaf(leaf):
    global logger
    logger.info("STARTING DEPLOYMENT: {}".format(leaf.hostname))
    try:
        switch = Switch(leaf.mgmt_address.split("/")[0], username, password)
        #move device to proper container
        logger.debug("Getting {} from CVP inventory based on serial number - {}".format(leaf.hostname, leaf.serial_number))
        device_dict = cvp.api.get_device_by_serial_number(leaf.serial_number)
        # print device_dict

        if device_dict is None or device_dict == {}:
            logger.error("{} with serial number {} could not be found in the inventory").format(leaf.hostname, leaf.serial_number)
            return

        switch.model = device_dict["modelName"]
        logger.debug("Updating {}'s chipset based on its model {}".format(leaf.hostname, switch.model))
        switch.update_chipset_by_model()
        
        #Check to see if device 
        # is still in undefined container
        if device_dict["containerName"] != "Undefined":
           logger.warning("{} is already out of the Undefined container".format(device_dict["hostname"]))
           return

        #Set Configlet Prefix
        configlet_prefix = "{}_".format(leaf.hostname)

        #configlets to apply
        configlets_to_apply = []

        #Build management configlet
        try:
            logger.info("Starting to build Management Configlet for {}".format(leaf.hostname))
            #Get terminattr statement for management configlet
            global telemetry_statement
            management_configlet =  telemetry_statement + "\n"
            logger.debug("Generating management configuration for {}".format(leaf.hostname))
            management_configlet += switch.build_management_configlet(leaf.hostname, leaf.mgmt_address,
                                                            default_route=global_options["MANAGEMENT"]["Default Gateway"],
                                                            management_interface=leaf.mgmt_interface,
                                                            vrf=global_options["MANAGEMENT"]["VRF"],
                                                            vrf_rd=global_options["MANAGEMENT"]["VRF Route-Distinguisher"],
                                                            cvp_node_addresses=None,
                                                            cvp_ingest_key=None)
            logger.debug("Successfully generated management configuration for {}".format(leaf.hostname))
            configlet_name = configlet_prefix + "MGMT"
            logger.debug("Updating {} configlet in CVP".format(configlet_name))
            updateInCVP(cvp, configlet_name, management_configlet, leaf.serial_number, apply=False)
            logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
            # printConfiglet(configlet_name, management_configlet)
            configlet_info = cvp.api.get_configlet_by_name(configlet_name)
            configlets_to_apply.append(configlet_info)
            logger.info("Completed building Management Configlet for {}".format(leaf.hostname))
        except Exception as e:
            logger.error("Error configuring Managment Configlet for {}".format(leaf.hostname))
            logger.error("Error:{}".format(str(e)))
            logger.error("Stopping deployment for {}".format(leaf.hostname))
            return

        #Build mlag config
        #Create mlag configlet and ibgp between mlag configlet
        if leaf.mlag_peer != "":
            try:
                logger.info("Building MLAG Configlet for {}".format(leaf.hostname))
                #get mlag variables
                logger.debug("Retrieving MLAG variables for {}".format(leaf.hostname))
                mlag_domain_id = global_options["MLAG"]["Domain ID"]    
                mlag_svi_address_range = global_options["MLAG"]["SVI Address Range"]
                mlag_port_channel_number = int(global_options["MLAG"]["Port-Channel Number"])
                mlag_vlan = int(global_options["MLAG"]["Vlan"])
                mlag_trunk_group_name = global_options["MLAG"]["Trunk Group Name"]
                virtual_mac_address = global_options["MLAG"]["Virtual Mac Address"]
                dual_primary_detection_delay = int(global_options["MLAG"]["Dual Primary Detection Delay"]) if global_options["MLAG"]["Dual Primary Detection Delay"] != "" else None
                dual_primary_detection_action = global_options["MLAG"]["Dual Primary Detection Action"] if global_options["MLAG"]["Dual Primary Detection Action"] != "" else None
                heartbeat_address = leaf.mlag_peer_mgmt_address.split("/")[0] if global_options["MLAG"]["Peer Address Heartbeat"] != "" else None
                heartbeat_vrf = global_options["MANAGEMENT"]["VRF"] if global_options["MANAGEMENT"]["VRF"] != "default" else None

                mgmt_ip_address = leaf.mgmt_address.split("/")[0]
                mlag_peer_mgmt_ip_address = leaf.mlag_peer_mgmt_address.split("/")[0]

                logger.debug("Successfully retrieved MLAG variables for {}".format(leaf.hostname))
                #Device with lower management IP address will get the .0 address
                if mgmt_ip_address < mlag_peer_mgmt_ip_address:
                    role = "primary"
                    logger.debug("Assigning Primary role for {}".format(leaf.hostname))
                #Device with higher management IP address will get the .1 address
                else:
                    role = "secondary"
                    logger.debug("Assigning Secondary role for {}".format(leaf.hostname))

                # print "Creating MLAG configlet"
                #MLAG
                logger.debug("Generating MLAG configuration for {}".format(leaf.hostname))
                mlag_configlet = switch.build_mlag(role, mlag_domain_id=mlag_domain_id, mlag_svi_address_range=mlag_svi_address_range,
                                                    interfaces=leaf.mlag_interfaces, port_channel=mlag_port_channel_number,
                                                    vlan=mlag_vlan, trunk_group_name=mlag_trunk_group_name, virtual_mac=virtual_mac_address,
                                                    dual_primary_detection_action=dual_primary_detection_action,
                                                    dual_primary_detection_delay=dual_primary_detection_delay, heartbeat_address=heartbeat_address,
                                                    heartbeat_vrf=heartbeat_vrf)
                logger.debug("Successfully generated MLAG configuration for {}".format(leaf.hostname))

                configlet_name = configlet_prefix + "MLAG"
                logger.debug("Updating {} configlet in CVP".format(configlet_name))
                updateInCVP(cvp, configlet_name, str(mlag_configlet), leaf.serial_number, apply=False)
                logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                # printConfiglet(configlet_name, mlag_configlet)
                configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                configlets_to_apply.append(configlet_info)
                logger.info("Completed building Management Configlet for {}".format(leaf.hostname))
            except Exception as e:
                logger.error("Error configuring MLAG Configlet for {}".format(leaf.hostname))
                logger.error("Error: {}".format(str(e)))

            #IBGP
            try:
                #get IBGP specific info
                ibgp_enabled = bool(int(global_options["IBGP Between MLAG Peers"]["IBGP"]))
                if ibgp_enabled == True:
                    logger.info("Building IBGP Configlet for {}".format(leaf.hostname))
                    logger.debug("Retrieving IBGP variables for {}".format(leaf.hostname))
                    ibgp_peering_svi = int(global_options["IBGP Between MLAG Peers"]["Peering SVI"])
                    ibgp_address_range = global_options["IBGP Between MLAG Peers"]["SVI Address Range"]
                    ibgp_peer_group_name = global_options["IBGP Between MLAG Peers"]["Peer Group Name"]
                    ibgp_pwd = global_options["IBGP Between MLAG Peers"]["Password"] if global_options["IBGP Between MLAG Peers"]["Password"] != "" else None
                    router_id = leaf.underlay_address.split("/")[0]
                    mlag_port_channel_number = int(global_options["MLAG"]["Port-Channel Number"])
                    logger.debug("Successfully retrieved IBGP variables for {}".format(leaf.hostname))
                    logger.debug("Generating IBGP configuration for {}".format(leaf.hostname))
                    ibgp_between_mlag_configlet = switch.build_ibgp_between_mlag(role, leaf.asn, router_id,
                                                            mlag_port_channel_number,
                                                            ibgp_address_range=ibgp_address_range,
                                                            svi=ibgp_peering_svi,
                                                            peer_group_name=ibgp_peer_group_name,
                                                            pwd=ibgp_pwd, max_routes=12000)
                    logger.debug("Successfully generated IBGP configuration for {}".format(leaf.hostname))
                    configlet_name = configlet_prefix + "IBGP_Between_MLAGs"
                    logger.debug("Updating {} configlet in CVP".format(configlet_name))
                    updateInCVP(cvp, configlet_name, ibgp_between_mlag_configlet, leaf.serial_number, apply=False)
                    logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                    # printConfiglet(configlet_name, ibgp_between_mlag_configlet)
                    configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                    configlets_to_apply.append(configlet_info)
                    logger.info("Completed building IBGP Configlet for {}".format(leaf.hostname))
            except Exception as e:
                logger.error("Error configuring IBGP Between MLAG Pair Configlet for {}".format(leaf.hostname))
                logger.error("Error: {}".format(str(e)))

        #Build IP Interface Underlay config
        try:
            logger.info("Building IP Interface Configlet for {}".format(leaf.hostname))
            logger.debug("Retrieving connection detail variables for {}".format(leaf.hostname))
            spine_connections_info = leaf.prep_spine_connection_info_for_configlet_builder()
            logger.debug("Successfully retrieved connection detail variables for {}".format(leaf.hostname))
            logger.debug("Generating IP Interface configuration for {}".format(leaf.hostname))
            ip_interface_configlet = switch.build_ip_interface_underlay(spine_connections_info, mtu_size=9214)
            logger.debug("Successfully generated IP Interface configuration for {}".format(leaf.hostname))
            configlet_name = configlet_prefix + "IP_Interfaces"
            logger.debug("Updating {} configlet in CVP".format(configlet_name))
            updateInCVP(cvp, configlet_name, ip_interface_configlet, leaf.serial_number, apply=False)
            logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
            # printConfiglet(configlet_name, ip_interface_configlet)
            configlet_info = cvp.api.get_configlet_by_name(configlet_name)
            configlets_to_apply.append(configlet_info)
            logger.info("Completed building IP Interface Configlet for {}".format(leaf.hostname))
        except Exception as e:
            logger.error("Error configuring IP Interfaces Configlet for {}".format(leaf.hostname))
            logger.error("Error: {}".format(str(e)))

        #Build BGP underlay config
        try:
            logger.info("Building Underlay Configlet for {}".format(leaf.hostname))
            logger.debug("Retrieving neighbor detail variables for {}".format(leaf.hostname))
            bgp_underlay_neighbor_info = leaf.prep_bgp_underlay_neighbor_info() #format source interface
            logger.debug("Successfully retrieved neighbor detail variables for {}".format(leaf.hostname))

            logger.debug("Retrieving underlay variables for {}".format(leaf.hostname))
            underlay_source_interface = global_options["GENERAL"]["Underlay Source Interface"]
            peer_group_name = global_options["BGP"]["Underlay Peer Group Name"]
            pwd = global_options["BGP"]["Password"] if global_options["BGP"]["Password"] != "" else None
            bfd = True if bool(int(global_options["BGP"]["BFD in Underlay"])) == True else False
            #Create underlay prefix list subnet
            local_transit_addresses = []
            for connection_info in leaf.spine_connection_info.values():
                if connection_info["local"]["IP Address"] != "":
                    local_transit_addresses.append(connection_info["local"]["IP Address"])
            transit_range = get_common_subnet(local_transit_addresses)
            # print(transit_range)
            transit_range = transit_range if transit_range is not None else "10.0.0.0/8"
            
            #Build route map info
            underlay_pl_name = global_options["BGP"]["Underlay Prefix List Name"] if global_options["BGP"]["Underlay Prefix List Name"] != "" else None
            loopback_pl_name = global_options["BGP"]["Loopback Prefix List Name"] if global_options["BGP"]["Loopback Prefix List Name"] != "" else None 

            if underlay_pl_name is not None and loopback_pl_name is not None:
                underlay_pl = {underlay_pl_name:["seq 10 permit {} le 31".format(transit_range)]}
                loopback_pl = {loopback_pl_name: ["seq 10 permit {} eq 32".format(leaf.underlay_address)]}
                if leaf.overlay_address is not None and leaf.overlay_address != "":
                    loopback_pl[loopback_pl_name].append("seq 20 permit {} eq 32".format(leaf.overlay_address))
                prefix_lists = [underlay_pl, loopback_pl]
            else:
                prefix_lists = None

            route_map_name = global_options["BGP"]["Route-Map Name"] if global_options["BGP"]["Route-Map Name"] != "" else None
            if route_map_name is not None and prefix_lists is not None:
                route_map = {route_map_name:[{"permit 10": "match ip address prefix-list {}".format(loopback_pl_name)},
                                             {"permit 20": "match ip address prefix-list {}".format(underlay_pl_name)}]}
            else:
                route_map = None

            logger.debug("Successfully retrieved underlay variables for {}".format(leaf.hostname))
            # print "Route-map", route_map
            # print "Prefix lists", prefix_lists
            logger.debug("Generating Underlay configuration for {}".format(leaf.hostname))
            bgp_underlay_configlet = switch.build_leaf_bgp(leaf.asn, "ipv4", leaf.underlay_address,
                                                                bgp_underlay_neighbor_info, underlay_source_interface=global_options["GENERAL"]["Underlay Source Interface"],
                                                                peer_group_name=peer_group_name,
                                                                pwd=pwd, bfd=bfd, max_routes=12000, route_map=route_map,
                                                                prefix_lists=prefix_lists)
            logger.debug("Successfully generated Underlay configuration for {}".format(leaf.hostname))
            configlet_name = configlet_prefix + "BGP_Underlay"
            logger.debug("Updating {} configlet in CVP".format(configlet_name))
            updateInCVP(cvp, configlet_name, bgp_underlay_configlet, leaf.serial_number, apply=False)
            logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
            # printConfiglet(configlet_name, bgp_underlay_configlet)
            configlet_info = cvp.api.get_configlet_by_name(configlet_name)
            configlets_to_apply.append(configlet_info)
            logger.info("Completed building Underlay Configlet for {}".format(leaf.hostname))
        except Exception as e:
            logger.error("Error configuring BGP Underlay Configlet for {}".format(leaf.hostname))
            logger.error("Error: {}".format(str(e)))

        #Build Overlay configlets
        logger.debug("Vxlan option:", global_options["VXLAN"]["Vxlan Data Plane"])
        if bool(int(global_options["VXLAN"]["Vxlan Data Plane"])) == True:
            #Build data plane
            try:
                logger.info("Building Overlay Data Plane Configlet for {}".format(leaf.hostname))
                logger.debug("Retrieving Overlay Data Plane variables for {}".format(leaf.hostname))
                overlay_source_interface = global_options["GENERAL"]["Overlay Source Interface"]
                vxlan_source_port = int(global_options["VXLAN"]["UDP Port"])
                vxlan_control_plane = global_options["VXLAN"]["Vxlan Control Plane"]
                logger.debug("Successfully retrieved Overlay Data Plane variables for {}".format(leaf.hostname))
                logger.debug("Generating Overlay Data Plane configuration for {}".format(leaf.hostname))
                vxlan_data_plane_configlet = switch.build_vxlan_data_plane(leaf.overlay_address, port=vxlan_source_port,
                                                                        overlay_source_interface=overlay_source_interface)
                logger.debug("Successfully generated Overlay Data Plane configuration for {}".format(leaf.hostname))

                configlet_name = configlet_prefix + "Vxlan_Data_Plane"
                logger.debug("Updating {} configlet in CVP".format(configlet_name))
                updateInCVP(cvp, configlet_name, vxlan_data_plane_configlet, leaf.serial_number, apply=False)
                logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                # printConfiglet(configlet_name, vxlan_data_plane_configlet)
                configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                configlets_to_apply.append(configlet_info)
                logger.info("Completed building Overlay Data Plane Configlet for {}".format(leaf.hostname))
            except Exception as e:
                logger.error("Error configuring Overlay Data Plane Configlet for {}".format(leaf.hostname))
                logger.error("Error: {}".format(str(e)))

            #Build control plane
            try:
                logger.info("Building Overlay Control Plane Configlet for {}".format(leaf.hostname))
                control_plane = global_options["VXLAN"]["Vxlan Control Plane"]
                if control_plane == "cvx":
                    logger.debug("Building Overlay Control Plane for {} using CVX as the controller".format(leaf.hostname))
                    logger.debug("Retrieving CVX control plane variables for {}".format(leaf.hostname))
                    cvx_addresses = []
                    primary_cvx_address = global_options["CVX"]["Primary CVX IP Address"] if "Primary CVX IP Address" in list(global_options["CVX"]) else None
                    secondary_cvx_address = global_options["CVX"]["Secondary CVX IP Address"] if "Secondary CVX IP Address" in list(global_options["CVX"]) else None
                    tertiary_cvx_address = global_options["CVX"]["Tertiary CVX IP Address"] if "Tertiary CVX IP Address" in list(global_options["CVX"]) else None
                    for address in [primary_cvx_address, secondary_cvx_address, tertiary_cvx_address]:
                        if address is not None and address != "":
                            cvx_addresses.append(address)
                    logger.debug("Successfully retrieved CVX control plane variables for {}".format(leaf.hostname))
                    logger.debug("Generating CVX control plane configuration for {}".format(leaf.hostname))
                    vxlan_control_plane_configlet = switch.build_cvx_vxlan_control_plane(cvx_addresses, global_options["GENERAL"]["Underlay Source Interface"])
                    logger.debug("Successfully generated CVX control plane configuration for {}".format(leaf.hostname))

                elif control_plane == "evpn":
                    logger.debug("Building Overlay Control Plane for {} using EVPN for controller".format(leaf.hostname))
                    logger.debug("Retrieving neighbor detail variables for {}".format(leaf.hostname))
                    bgp_overlay_neighbor_info = leaf.prep_bgp_overlay_neighbor_info()
                    logger.debug("Successfully retrieved neighbor detail variables for {}".format(leaf.hostname))

                    logger.debug("Retrieving EVPN Control Plane variables for {}".format(leaf.hostname))
                    evpn_model = global_options["EVPN"]["Model"]
                    underlay_source_interface = global_options["GENERAL"]["Underlay Source Interface"]
                    peer_group_name = global_options["BGP"]["Overlay Peer Group Name"]
                    mlag_peer_group_name = global_options["IBGP Between MLAG Peers"]["Peer Group Name"]
                    pwd = global_options["BGP"]["Password"] if global_options["BGP"]["Password"] != "" else None
                    bfd = True if bool(int(global_options["BGP"]["BFD in Overlay"])) == True else False
                    vrfs_info = None
                    mlag_port_channel = None

                    if evpn_model == "symmetric":
                        #is MLAG enabled
                        if leaf.mlag_peer is not None and leaf.mlag_peer != "":
                            mlag_enabled = True   
                            mgmt_ip_address =leaf.mgmt_address.split("/")[0]
                            mlag_peer_mgmt_ip_address =leaf.mlag_peer_mgmt_address.split("/")[0]
                            #Device with lower management IP address will get the .0 address
                            if mgmt_ip_address < mlag_peer_mgmt_ip_address:
                                role = "primary"
                            #Device with higher management IP address will get the .1 address
                            else:
                                role = "secondary"
                        else:
                            mlag_enabled = False
                            role = None
                        mlag_port_channel = int(global_options["MLAG"]["Port-Channel Number"])
                        #Prep vrfs_info
                        vrfs_info = {}
                        for vrf, vrf_info in global_options["Vrfs"].items():
                            tmp_vrf_info = {}
                            tmp_vrf_info["Vlan"] = vrf_info["Vlan"]
                            tmp_vrf_info["VNI"] = vrf_info["VNI"]
                            tmp_vrf_info["SVI Address Range"] = vrf_info["SVI Address Range"]
                            tmp_vrf_info["Route Target"] = vrf_info["Route Target"]
                            
                            vrf_rd = vrf_info["Route Distinguisher"]
                            option_decoder = {"Underlay Address":leaf.underlay_address.split("/")[0],
                                                "VNI": "vni", "Vlan": "vlan"}
                            rd = str(option_decoder[vrf_rd.split(":")[0]]) + ":" + str(vrf_rd.split(":")[1])
                            # rt = str(option_decoder[vrf_rt.split(":")[0]]) + ":" + str(option_decoder[vrf_rt.split(":")[0]])
                            tmp_vrf_info["Route Distinguisher"] = rd
                            vrfs_info[vrf] = tmp_vrf_info
                    logger.debug("Successfully retrieved EVPN control plane variables for {}".format(leaf.hostname))
                    logger.debug("Generating EVPN control plane configuration for {}".format(leaf.hostname))
                    vxlan_control_plane_configlet = switch.build_leaf_bgp(leaf.asn, "evpn", leaf.underlay_address,
                                                    bgp_overlay_neighbor_info, 
                                                    underlay_source_interface=underlay_source_interface, peer_group_name=peer_group_name,
                                                    mlag_peer_group_name=mlag_peer_group_name, pwd=pwd,
                                                    bfd=bfd, vrfs=vrfs_info, role=role, mlag_peer_link=mlag_port_channel)
                    logger.debug("Successfully generated EVPN control plane configuration for {}".format(leaf.hostname))
                elif control_plane == "her":
                    logger.debug("Building Overlay Control Plane for {} using HER".format(leaf.hostname))
                    logger.debug("VTEP list: {}".format(vtep_peers))
                    logger.debug("Generating HER control plane configuration for {}".format(leaf.hostname))
                    vxlan_control_plane_configlet = switch.build_her_vxlan_control_plane(vtep_peers)
                    logger.debug("Successfully generated HER control plane configuration for {}".format(leaf.hostname))

                else:
                    logger.warning("{} is an INVALID control plane option".format(control_plane))
                    vxlan_control_plane_configlet = None

                if vxlan_control_plane_configlet is not None:
                    configlet_name = configlet_prefix + "Vxlan_Control_Plane"
                    logger.debug("Updating {} configlet in CVP".format(configlet_name))
                    updateInCVP(cvp, configlet_name, vxlan_control_plane_configlet, leaf.serial_number, apply=False)
                    logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                    # printConfiglet(configlet_name, vxlan_control_plane_configlet)
                    configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                    configlets_to_apply.append(configlet_info)
                    logger.info("Completed building Overlay Control Plane Configlet for {}".format(leaf.hostname))
            except Exception as e:
                logger.error("Error configuring Overlay Control Plane Configlet for {}".format(leaf.hostname))
                logger.error("Error: {}".format(str(e)))

        #Build NAT Configlet
        try:
            if leaf.nat_address is not None:
                logger.info("Building NAT Configlet for {}".format(leaf.hostname))
                vrf = list(global_options["Vrfs"])[0]
                logger.debug("Generating NAT configuration for {}".format(leaf.hostname))
                nat_configlet = ""
                nat_configlet += "vrf instance {}\n".format(vrf)
                nat_configlet += "!\n"
                nat_configlet += "interface {}\n".format(global_options["GENERAL"]["NAT Loopback"])
                nat_configlet += "   description NAT source for uniqueness\n"
                nat_configlet += "   vrf {}\n".format(vrf)
                nat_configlet += "   ip address {}\n".format(leaf.nat_address)
                nat_configlet += "!\n"
                nat_configlet += "ip address virtual source-nat vrf {} address {}".format(vrf, leaf.nat_address.split("/")[0])
                logger.debug("Successfully generated NAT configuration for {}".format(leaf.hostname))

                configlet_name = configlet_prefix + "NAT_Info"
                logger.debug("Updating {} configlet in CVP".format(configlet_name))
                updateInCVP(cvp, configlet_name, nat_configlet, leaf.serial_number, apply=False)
                logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                # printConfiglet(configlet_name, nat_configlet)
                configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                configlets_to_apply.append(configlet_info)
                logger.info("Completed building NAT Configlet for {}".format(leaf.hostname))
        except Exception as e:
            logger.error("Error configuring NAT Configlet for {}".format(leaf.hostname))
            logger.error("Error: {}".format(str(e)))
        
        #Check config is valid
        configlet_keys = [ configlet["key"] for configlet in configlets_to_apply ]
        logger.info("Validating configuration for {}...".format(leaf.hostname))
        validation = cvp.api.validate_configlets_for_device(device_dict["systemMacAddress"], configlet_keys, page_type="validate")

        if type(validation["errors"]) == list and len(validation["errors"]) > 0:
            errors = True
        else:
            errors = False

        if errors == True and execute_tasks==True:
            logger.error("Errors found in configuration for {}.  Will not execute tasks for this device.  View designed config on device in CVP to see error.".format(leaf.hostname))
        elif errors == True and execute_tasks == False:
            logger.warning("Errors found in configuration for {}.  View designed config on device in CVP to see error.".format(leaf.hostname))
        else:
            logger.info("Configuration is valid for {}".format(leaf.hostname))

        #Check to see if device should get deployed with image
        # print device_dict["containerName"]
        # print "Leaf image bundle:", leaf.image_bundle
        # logger.debug("Configlets to apply:", configlets_to_apply)
        logger.info("Initializing deploy device task for {}...".format(leaf.hostname))
        if device_dict["containerName"] == "Undefined":
            response = cvp.api.deploy_device(device_dict, leaf.container_name, configlets=configlets_to_apply, image=leaf.image_bundle)
        else:
            response = cvp.api.deploy_device(device_dict, leaf.container_name, configlets=configlets_to_apply)
        logger.info("Initialized deploy device task for {}".format(leaf.hostname))

        if execute_tasks == True and errors == False:
            logger.info("Executing tasks...")
            if "data" in list(response):
                if "taskIds" in list(response["data"]):
                    for task_id in response["data"]["taskIds"]:
                        try:
                            logger.info("Executing task {}".format(task_id))
                            cvp.api.execute_task(task_id)
                            logger.info("Successfully executed {}".format(task_id))
                        except Exception as e:
                            logger.error("Error executing tasks related to {}".format(leaf.hostname))
                            logger.error("Error: {}".format(str(e)))
        logger.info("FINISHED DEPLOYMENT: {}".format(leaf.hostname))        
    except KeyboardInterrupt:
        print("Received KeyboardInterrupt")
        sys.exit()
    except Exception as e:
        logger.error("Error creating configlets for {}".format(leaf.hostname))
        logger.error("Error: {}".format(str(e)))
    
    return

#########################################################################################################

def deployL3LSSpine(spine):
    global logger
    logger.info("STARTING DEPLOYMENT: {}".format(spine.hostname))
    try:
        switch = Switch(spine.mgmt_address.split("/")[0], username, password)
        #move device to proper container
        logger.info("Getting {} from CVP inventory based on serial number - {}".format(spine.hostname, spine.serial_number))
        device_dict = cvp.api.get_device_by_serial_number(spine.serial_number)

        if device_dict is None or device_dict == {}:
            logger.error("{} with serial number {} could not be found in the inventory".format(spine.hostname, spine.serial_number))
            return

        switch.model = device_dict["modelName"]
        logger.debug("Updating {}'s chipset based on its model {}".format(spine.hostname, switch.model))
        switch.update_chipset_by_model()
        
        #Set Configlet Prefix
        configlet_prefix = "{}_".format(spine.hostname)

        #configlets to apply
        configlets_to_apply = []

        #Check to see if device is still in undefined container
        if (device_dict["containerName"] != "Undefined"):
            try:
                logger.warning("{} is already out of the Undefined container".format(spine.hostname))
                logger.warning("Only modifying IP Interface Configlet for {}".format(spine.hostname))
                configlet_name = configlet_prefix + "IP_Interfaces"
                logger.debug("Retrieving existing IP interface configlet with name {} for {}".format(configlet_name, spine.hostname))
                ip_interface_configlet = cvp.api.get_configlet_by_name(configlet_name)
                if ip_interface_configlet is None:
                    logger.warning("Unable to find existing {} configlet for {}".format(configlet_name, spine.hostname))
                #Create new IP interface configlets
                logger.debug("Retrieving connection detail variables for {}".format(spine.hostname))
                spine_connections_info = spine.prep_leaf_connection_info_for_configlet_builder()
                logger.debug("Successfully retrieved connection detail variables for {}".format(spine.hostname))

                logger.debug("Generating IP Interface configuration for {}".format(spine.hostname))
                ip_interface_config = switch.build_ip_interface_underlay(spine_connections_info, mtu_size=9200)
                logger.debug("Successfully generated IP Interface configuration for {}".format(spine.hostname))
                if ip_interface_configlet is not None:
                    logger.debug("Merging new IP interface configuration with existing IP interface configuration")
                    ip_interface_config = "!\n" + ip_interface_config
                    ip_interface_config = mergeInterfaceConfigs(ip_interface_config, ip_interface_configlet["config"])
                    logger.debug("Successfully merged new IP interface configuration with existing IP interface configuration")

                configlet_name = configlet_prefix + "IP_Interfaces"
                logger.debug("Updating {} configlet in CVP".format(configlet_name))
                updateInCVP(cvp, configlet_name, ip_interface_config, spine.serial_number, apply=False)
                logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                # printConfiglet(configlet_name, ip_interface_configlet["config"])
                configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                configlets_to_apply.append(configlet_info)
                logger.info("Completed modifying IP Interface Configlet for {}".format(spine.hostname))
            except Exception as e:
                logger.error("Error modifying IP Interface Configlet for {}".format(spine.hostname))
                logger.error("Error: {}".format(str(e)))
            
        else:
            #Build management configlet
            try:
                logger.info("Starting to build Management Configlet for {}".format(spine.hostname))
                #Get terminattr statement for management configlet
                global telemetry_statement
                management_configlet =  telemetry_statement + "\n"
                logger.debug("Generating management configuration for {}".format(spine.hostname))
                management_configlet = switch.build_management_configlet(spine.hostname, spine.mgmt_address,
                                                                default_route=global_options["MANAGEMENT"]["Default Gateway"],
                                                                management_interface=spine.mgmt_interface,
                                                                vrf=global_options["MANAGEMENT"]["VRF"],
                                                                vrf_rd=global_options["MANAGEMENT"]["VRF Route-Distinguisher"],
                                                                cvp_node_addresses=global_options["CVP"]["CVP Addresses"],
                                                                cvp_ingest_key=None)
                logger.debug("Successfully generated management configuration for {}".format(spine.hostname))
                configlet_name = configlet_prefix + "MGMT"
                logger.debug("Updating {} configlet in CVP".format(configlet_name))
                updateInCVP(cvp, configlet_name, management_configlet, spine.serial_number, apply=False)
                logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                # printConfiglet(configlet_name, management_configlet)
                configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                configlets_to_apply.append(configlet_info)
                logger.info("Completed building Management Configlet for {}".format(spine.hostname))
            except Exception as e:
                logger.error("Error configuring Managment Configlet for {}".format(spine.hostname))
                logger.error("Error:{}".format(str(e)))
                logger.error("Stopping deployment for {}".format(spine.hostname))
                return

            #Build IP Interface Underlay config
            try:
                logger.info("Building IP Interface Configlet for {}".format(spine.hostname))
                logger.debug("Retrieving existing IP interface configlet with name {} for {}".format(configlet_name, spine.hostname))
                spine_connections_info = spine.prep_leaf_connection_info_for_configlet_builder()
                logger.debug("Successfully retrieved connection detail variables for {}".format(spine.hostname))
                logger.debug("Generating IP Interface configuration for {}".format(spine.hostname))
                ip_interface_configlet = switch.build_ip_interface_underlay(spine_connections_info, mtu_size=9214)
                logger.debug("Successfully generated IP Interface configuration for {}".format(spine.hostname))
                configlet_name = configlet_prefix + "IP_Interfaces"
                logger.debug("Updating {} configlet in CVP".format(configlet_name))
                updateInCVP(cvp, configlet_name, ip_interface_configlet, spine.serial_number, apply=False)
                logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                # printConfiglet(configlet_name, ip_interface_configlet)
                configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                configlets_to_apply.append(configlet_info)
                logger.info("Completed building IP Interface Configlet for {}".format(spine.hostname))
            except Exception as e:
                logging.error("Error configuring IP Interface Configlet for {}".format(spine.hostname))
                logger.error("Error:{}".format(str(e)))

            #Build BGP underlay config
            try:
                logger.info("Building Underlay Configlet for {}".format(spine.hostname))
                logger.debug("Retrieving neighbor detail variables for {}".format(spine.hostname))
                underlay_source_interface = global_options["GENERAL"]["Underlay Source Interface"]
                peer_group_name = global_options["BGP"]["Underlay Peer Group Name"]
                peer_filter_name = global_options["BGP"]["Spine Peer Filter Name"]
                remote_ases_and_neighbors = spine.prep_bgp_connection_info_for_configlet_builder()
                bfd = True if bool(int(global_options["BGP"]["BFD in Underlay"])) == True else False
                pwd = global_options["BGP"]["Password"] if global_options["BGP"]["Password"] != "" else None

                #Build route map info
                underlay_pl_name = global_options["BGP"]["Underlay Prefix List Name"] if global_options["BGP"]["Underlay Prefix List Name"] != "" else None
                loopback_pl_name = global_options["BGP"]["Loopback Prefix List Name"] if global_options["BGP"]["Loopback Prefix List Name"] != "" else None 

                if underlay_pl_name is not None and loopback_pl_name is not None:
                    underlay_pl = {underlay_pl_name:["seq 10 permit {} le 31".format(spine.transit_ip_range)]}
                    loopback_pl = {loopback_pl_name: ["seq 10 permit {} eq 32".format(spine.underlay_address)]}
                    prefix_lists = [underlay_pl, loopback_pl]
                else:
                    prefix_lists = None

                route_map_name = global_options["BGP"]["Route-Map Name"] if global_options["BGP"]["Route-Map Name"] != "" else None
                if route_map_name is not None and prefix_lists is not None:
                    route_map = {route_map_name:[{"permit 10": "match ip address prefix-list {}".format(loopback_pl_name)},
                                                {"permit 20": "match ip address prefix-list {}".format(underlay_pl_name)}]}
                else:
                    route_map = None

                logger.debug("Successfully retrieved underlay variables for {}".format(spine.hostname))
                logger.debug("Generating Underlay configuration for {}".format(spine.hostname))
                bgp_underlay_configlet = switch.build_dynamic_spine_bgp(spine.asn,
                                                                        "ipv4", spine.ecmp_paths, spine.underlay_address,
                                                                        spine.asn_range, spine.transit_ip_range,
                                                                        route_map=route_map, prefix_lists=prefix_lists,
                                                                        underlay_source_interface=underlay_source_interface,
                                                                        router_id=spine.underlay_address.split("/")[0],
                                                                        peer_group_name=peer_group_name,
                                                                        peer_filter_name=peer_filter_name, pwd=pwd, max_routes=12000,
                                                                        bfd=bfd)
                logger.debug("Successfully generated Underlay configuration for {}".format(spine.hostname))
                configlet_name = configlet_prefix + "BGP_Underlay"
                logger.debug("Updating {} configlet in CVP".format(configlet_name))
                updateInCVP(cvp, configlet_name, bgp_underlay_configlet, spine.serial_number, apply=False)
                logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                # printConfiglet(configlet_name, bgp_underlay_configlet)
                configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                configlets_to_apply.append(configlet_info)
                logger.info("Completed building Underlay Configlet for {}".format(spine.hostname))

            except Exception as e:
                logging.error("Error configuring BGP Underlay Configlet for {}".format(spine.hostname))
                logger.error("Error:{}".format(str(e)))


            if bool(int(global_options["VXLAN"]["Vxlan Data Plane"])) == True and global_options["VXLAN"]["Vxlan Control Plane"] == "evpn":
                #Build EVPN BGP config
                try:
                    logger.info("Building Overlay Control Plane for {} using EVPN for controller".format(spine.hostname))
                    logger.debug("Retrieving EVPN Control Plane variables for {}".format(spine.hostname))
                    underlay_source_interface = global_options["GENERAL"]["Underlay Source Interface"]
                    peer_filter_name = global_options["BGP"]["Spine Peer Filter Name"]
                    bfd = True if bool(int(global_options["BGP"]["BFD in Overlay"])) == True else False
                    pwd = global_options["BGP"]["Password"] if global_options["BGP"]["Password"] != "" else None
                    peer_group_name = global_options["BGP"]["Overlay Peer Group Name"]
                    logger.debug("Successfully retrieved EVPN control plane variables for {}".format(spine.hostname))
                    logger.debug("Generating EVPN control plane configuration for {}".format(spine.hostname))
                    bgp_overlay_configlet = switch.build_dynamic_spine_bgp(spine.asn,
                                                                        "evpn", spine.ecmp_paths, spine.underlay_address,
                                                                        spine.asn_range, spine.underlay_loopback_ip_range,
                                                                        underlay_source_interface=underlay_source_interface,
                                                                        router_id=spine.underlay_address.split("/")[0],
                                                                        peer_group_name=peer_group_name,
                                                                        peer_filter_name=peer_filter_name, pwd=pwd, max_routes=0,
                                                                        bfd=bfd)
                    logger.debug("Successfully generated EVPN control plane configuration for {}".format(spine.hostname))
                    configlet_name = configlet_prefix + "BGP_Overlay"
                    logger.debug("Updating {} configlet in CVP".format(configlet_name))
                    updateInCVP(cvp, configlet_name, bgp_overlay_configlet, spine.serial_number, apply=False)
                    logger.debug("Successfully updated {} configlet in CVP".format(configlet_name))
                    # printConfiglet(configlet_name, bgp_overlay_configlet)
                    configlet_info = cvp.api.get_configlet_by_name(configlet_name)
                    configlets_to_apply.append(configlet_info)
                    logger.info("Completed building Overlay Control Plane Configlet for {}".format(spine.hostname))
                except Exception as e:
                    logger.error("Error configuring BGP Overlay Configlet for {}".format(spine.hostname))
                    logger.error("Error:{}".format(str(e)))

        #Check config is valid
        configlet_keys = [ configlet["key"] for configlet in configlets_to_apply ]
        logger.info("Validating configuration for {}...".format(spine.hostname))
        validation = cvp.api.validate_configlets_for_device(device_dict["systemMacAddress"], configlet_keys, page_type="validate")

        if type(validation["errors"]) == list and len(validation["errors"]) > 0:
            errors = True
        else:
            errors = False

        if errors == True and execute_tasks==True:
            logger.error("Errors found in configuration for {}.  Will not execute tasks for this device.  View designed config on device in CVP to see error.".format(spine.hostname))
        elif errors == True and execute_tasks == False:
            logger.warning("Errors found in configuration for {}.  View designed config on device in CVP to see error.".format(spine.hostname))
        else:
            logger.info("Configuration is valid for {}".format(spine.hostname))

        #Check to see if device should get deployed with image
        logger.debug("Configlets to apply: {}".format(configlets_to_apply))
        if device_dict["containerName"] == "Undefined":
            logger.info("Initializing deploy device task for {}...".format(spine.hostname))
            response = cvp.api.deploy_device(device_dict, spine.container_name, configlets=configlets_to_apply, image=spine.image_bundle)
            logger.info("Initialized deploy device task for {}".format(spine.hostname))
        else:
            logger.info("Initializing deploy device task...".format(spine.hostname))
            response = cvp.api.deploy_device(device_dict, spine.container_name, configlets=configlets_to_apply)
            logger.info("Initialized deploy device task".format(spine.hostname))

        if execute_tasks == True and errors == False:
            logger.info("Executing tasks...")
            if "data" in list(response):
                if "taskIds" in list(response["data"]):
                    for task_id in response["data"]["taskIds"]:
                        try:
                            logger.info("Executing task {}".format(task_id))
                            cvp.api.execute_task(task_id)
                            logger.info("Successfully executed {}".format(task_id))
                        except Exception as e:
                            logger.error("Error executing tasks related to {}".format(spine.hostname))
                            logger.error("Error: {}".format(str(e)))
        logger.info("FINISHED DEPLOYMENT: {}".format(spine.hostname))
    except KeyboardInterrupt:
        print("Received KeyboardInterrupt")
        sys.exit()
    except Exception as e:
        print("Error creating Configlet for {}".format(spine.hostname))
        print("Error:", e)
    return

#########################################################################################################
def configureCVXForVxlan(cvx_address):
    try:
        switch = Switch(cvx_address.split("/")[0], username, password)
        switch.get_facts()
        cvx_config = switch.build_cvx_control_plane()
        configlet_prefix = "{}_".format(switch.hostname)
        configlet_name = configlet_prefix + "Vxlan_Control_Plane"
        task_ids = updateInCVP(cvp, configlet_name, cvx_config, switch.fqdn)
        print ("Execute tasks setting is set to", execute_tasks)
        print (len(task_ids), "task Ids:", task_ids)

        if execute_tasks == True:
            for task_id in task_ids:
                try:
                    cvp.api.execute_task(task_id)
                    print ("Executed {}".format(task_id))
                except Exception as e:
                    print ("Error executing tasks related to {}".format(cvx_address))
                    print ("Error:", e)
    except KeyboardInterrupt:
        print ("Received KeyboardInterrupt")
        sys.exit()
    except Exception as e:
        print ("Error creating CVX Configlet for {}".format(cvx_address))
        print ("Error:", e)

    return
#########################################################################################################

def addVlansToLeaf(leaf):
    try:
        switch = Switch(leaf.mgmt_address.split("/")[0], username, password)
        logger.info("Getting switch details")
        switch.get_facts()
        logger.info("Retrieved switch details")
        logger.info("Parsing vlan details")
        underlay_interface = global_options["GENERAL"]["Underlay Source Interface"]
        underlay_address = switch.interfaces[underlay_interface]["interfaceAddress"][0]["primaryIp"]["address"]
        vlans_info = {}
        for vlan, info in global_options["Vlans"].items():
            vlan_info = {}
            vlan_info["Name"] = info["Name"]
            vlan_info["SVI Address"] = info["SVI Address"]
            vlan_info["Vrf"] = info["Vrf"]
            vlan_info["Stretched"] = bool(int(info["Stretched"]))
            vlan_info["VNI"] = int(info["VNI"])
            if info["Route Distinguisher"] is not None and info["Route Distinguisher"] != "":
                rd_pre_colon = info["Route Distinguisher"].split(":")[0].strip()
                rd_post_colon = info["Route Distinguisher"].split(":")[1].strip()
                if rd_pre_colon == "Underlay Address":
                    vlan_info["Route Distinguisher"] = underlay_address + ":" + rd_post_colon
                else:
                    vlan_info["Route Distinguisher"] = None
            else:
                vlan_info["Route Distinguisher"] = None
            vlan_info["DHCP Helper Addresses"] = info["DHCP Helper Addresses"]
            vlans_info[vlan] = vlan_info
        
        #gathering values for options for mac vrf route distinguisher
        #options are either underlay address, overlay address, or bgp asn
        dhcp_helper_interface = global_options["GENERAL"]["NAT Loopback"]
        #set vlan info
        vlan_info = vlans_info
        #get vxlan data plan on/off value
        vxlan = global_options["VXLAN"]["Vxlan Data Plane"]
        evpn = True if global_options["VXLAN"]["Vxlan Control Plane"] == "evpn" else False
        #if using evpn for the vxlan control plane
        if evpn == True:
            evpn_model = global_options["EVPN"]["Model"]
            asn = switch.send_commands("show ip bgp vrf default | grep 'local AS number'")[0]["show ip bgp vrf default | grep 'local AS number'"].split(" ")[-1].strip()
        else:
            evpn_model = None
            asn = None

        logger.info("Parsed vlan details")

        configlet_prefix = "{}_".format(switch.hostname)
        configlet_name = configlet_prefix + "Vlans"
        logger.info("Generating vlan configuration")
        vlan_config = switch.add_vlans(vlan_info, vxlan=vxlan, evpn=evpn, evpn_model=evpn_model, 
                                            asn=asn, dhcp_helper_interface=dhcp_helper_interface)
        logger.info("Successfully generated vlan configuration")
        #Check to see if their is an existing vlan
        logger.info("Checking to see if vlan configlet already exists")
        try:
            configlet_exists = cvp.api.get_configlet_by_name(configlet_name)
        except:
            logger.info( "Configlet {} doesn't exist".format(configlet_name))
            configlet_exists = None

        if configlet_exists:
            logger.info("An existing vlan configlet already exists for {}".format(leaf.hostname))
            logger.info("Merging existing configlet {} with newly generated vlan configuration".format(configlet_exists["name"]))
            vlan_config = mergeVlanConfigs(vlan_config, configlet_exists["config"])
            logger.info("Successfully merged vlan configs")

        # printConfiglet(configlet_name, vlan_config)
        logger.info("Updating {} in CVP".format(configlet_name))
        task_ids = updateInCVP(cvp, configlet_name, vlan_config, leaf.serial_number)
        logger.info("Successfully updated {} in CVP".format(configlet_name))
        # print "Execute tasks setting is set to", execute_tasks
        # print len(task_ids), "task Ids:", task_ids
        if execute_tasks == True:
            for task_id in task_ids:
                try:
                    cvp.api.execute_task(task_id)
                    print( "Executed {}".format(task_id))
                except Exception as e:
                    print("Error executing tasks related to {}".format(leaf.hostname))
                    print("Error:", e)

    except KeyboardInterrupt:
        logger.error( "Received KeyboardInterrupt")
        sys.exit()
    except Exception as e:
        logger.error("Error creating Vlan Configlet for {}".format(leaf.hostname))
        logger.error("Error:", str(e))
    return

#########################################################################################################


def addVRFsToLeaf(leaf):
    try:
        switch = Switch(leaf.mgmt_address.split("/")[0], username, password)
        switch.get_facts()
        #gathering values for options router-id, vrf route distinguisher, route target
        asn = leaf.asn
        router_id = leaf.underlay_address.split("/")[0]
        #is MLAG enabled
        if leaf.mlag_peer is not None and leaf.mlag_peer != "":
            mlag_enabled = True   
            mgmt_ip_address = leaf.mgmt_address.split("/")[0]
            mlag_peer_mgmt_ip_address =leaf.mlag_peer_mgmt_address.split("/")[0]
            #Device with lower management IP address will get the .0 address
            if mgmt_ip_address < mlag_peer_mgmt_ip_address:
                role = "primary"
            #Device with higher management IP address will get the .1 address
            else:
                role = "secondary"
        else:
            mlag_enabled = False
            role = None
        #Prep vrfs_info
        vrfs_info = {}
        for vrf, vrf_info in global_options["Vrfs"].items():
            xcel_translations["vlan"] = global_options["Vrfs"][vrf]["Vlan"]
            rd_pre_colon = vrf_info["Route Distinguisher"].split(":")[0]
            rd_post_colon = vrf_info["Route Distinguisher"].split(":")[0]
            rt_pre_colon = vrf_info["Route Target"].split(":")[0]
            rt_post_colon = vrf_info["Route Target"].split(":")[0]
            for translation in xcel_translations:
                if translation == rd_pre_colon:
                    vrf_info["Route Distinguisher"] = vrf_info["Route Distinguisher"].replace(rd_pre_colon, xcel_translations[translation])
                    print(vrf_info["Route Distinguisher"])
                elif translation == rd_post_colon:
                    vrf_info["Route Distinguisher"].replace(rd_post_colon, xcel_translations[translation])
                elif translation == rt_pre_colon:
                    vrf_info["Route Target"].replace(rt_pre_colon, xcel_translations[translation])
                elif translation == rt_post_colon:
                    vrf_info["Route Target"].replace(rt_post_colon, xcel_translations[translation])
            vrfs_info[vrf] = vrf_info
        vrfs_info = global_options["Vrfs"]

        configlet_prefix = "{}_".format(switch.hostname)
        configlet_name = configlet_prefix + "VRFs"
        vrf_config = switch.add_vrfs(leaf.asn, router_id, mlag_enabled=mlag_enabled, role=role,
        vrfs_info=vrfs_info)

        #Check to see if their is an existing vrf
        try:
            configlet_exists = cvp.api.get_configlet_by_name(configlet_name)
        except:
            print ("Configlet {} doesn't exist".format(configlet_name))
            configlet_exists = None
        
        #If a configlet already exists
        # if configlet_exists != None:
        #     vrf_config = configlet_exists["config"] + vrf_config

        printConfiglet(configlet_name, vrf_config)

        task_ids = updateInCVP(cvp, configlet_name, vrf_config, switch.fqdn)

        print ("Execute tasks setting is set to", execute_tasks)
        print (len(task_ids), "task Ids:", task_ids)
        if execute_tasks == True:
            for task_id in task_ids:
                try:
                    cvp.api.execute_task(task_id)
                    print ("Executed {}".format(task_id))
                except Exception as e:
                    print("Error executing tasks related to {}".format(leaf.hostname))
                    print( "Error:", e)


    except KeyboardInterrupt:
        print( "Received KeyboardInterrupt")
        sys.exit()
    except Exception as e:
        print("Error creating Vrf Configlet for {}".format(leaf.hostname))
        print("Error:", e)
    return
#########################################################################################################
def cleanUpDeviceConfiglets(device):
    try:
        switch = Switch(device.mgmt_address.split("/")[0], username, password)
        switch.get_facts()
        
        #Probably not a good idea to mess around with management config (Could lost connectivity)
        # task_ids = cleanUpConfiglets(cvp, switch.fqdn, category="Management")

        task_ids = cleanUpConfiglets(cvp, switch.fqdn, category="Config")

        print("Execute tasks setting is set to", execute_tasks)
        print(len(task_ids), "task Ids:", task_ids)
        if execute_tasks == True:
            for task_id in task_ids:
                try:
                    cvp.api.execute_task(task_id)
                    print ("Executed {}".format(task_id))
                except Exception as e:
                    print("Error executing tasks related to {}".format(device.hostname))
                    print("Error:", e)

    except KeyboardInterrupt:
        print( "Received KeyboardInterrupt")
        sys.exit()
    except Exception as e:
        print( "Error Consolidating Configlet for {}".format(device.hostname))
        print("Error:", e)
    return

def get_telemetry_statement(cvp):
    global logger
    #get telemetry builder ID
    logger.debug("Retrieving existing configlets")
    configlet = cvp.api.get_configlet_by_name("SYS_TelemetryBuilderV3")
    if configlet is None:
        logger.error("SYS_TelemetryBuilderV3 does not exist.  Unable to generate TerminAttr configuration.")
        return
    builder_id = configlet['key']
    logger.debug("Successfully retrieved {}".format(len(configlet['name'])))

    logger.debug("SYS_TelemtryBuilder configlet id is {}".format(builder_id))
    #get config from telemetry builder
    if builder_id is not None:
        data = {
            "previewValues": [
                {
                "fieldId": "vrf",
                "value": global_options["MANAGEMENT"]["VRF"]
                }
            ],
            "configletBuilderId": builder_id,
            "netElementIds": [],
            "pageType": "netelement",
            "containerId": "",
            "containerToId": "",
            "mode": "preview"
            }
    try:
        logger.debug("Generating TerminAttr statement for devices")
        return  cvp.api.generate_configlet_builder_preview(data)["data"]
    except:
        return None

def run_script(operation=None,autoexec=None,cvpuser=None,cvppass=None):
    global username
    global password
    global execute_tasks
    option=int(operation)
    execute_tasks = bool(int(autoexec))
    username=cvpuser
    password=cvppass
    global cvp
    global global_options
    global logger
    global telemetry_statement
    # import time
    # logger.info("bleh")
    # time.sleep(5)
    # logger.info("bleh")
    # time.sleep(5)
    # logger.info("bleh")
    # return
    logger.info("Parsing spreadsheet")
    info_location = "./workbook.xls"
    leafs = parseLeafInfoExcel(info_location, logger)
    if leafs is None:
        logger.error("FAILED: Unable to parse leafs from spreadsheet.")
        return
    spines = parseSpineInfoExcel(info_location, logger)
    if spines is None:
        logger.error("FAILED: Unable to parse spines from spreadsheet.")
        return
    day_2_target_devices = parseDay2Targets(info_location, logger)
    if day_2_target_devices is None:
        logger.error("FAILED: Unable to parse day 2 target devices from spreadsheet.")
        return
    global_options = parseGeneralInfoExcel(info_location, logger)
    if global_options is None:
        logger.error("FAILED: Unable to parse global variables from spreadsheet.")
        return
    global_options = cleanup_variable_values(global_options, logger)
    if global_options is None:
        logger.error("FAILED: Missing keys in 'Global Variables L3LS' sheet.")
        return

    #Update P2P connection info
    for i, spine in enumerate(spines):
        for leaf in leafs:
            #Update spine with leaf neighbor info
            if spine.point_to_point_neighbor_info is None:
                spine.point_to_point_neighbor_info = []
            neighbor_address = leaf.spine_connection_info[i+1]["local"]["IP Address"]
            spine_inteface = leaf.spine_connection_info[i+1]["remote"]["Interface"]
            spine_interface_address = leaf.spine_connection_info[i+1]["remote"]["IP Address"]
            leaf_interface = leaf.spine_connection_info[i+1]["local"]["Interface"]
            #Update Spine with leaf info
            neighbor_info = {"Local Interface": spine_inteface, "Local IP Address": spine_interface_address, "Neighbor IP Address": neighbor_address, "Neighbor ASN": leaf.asn, "Neighbor EVPN Transit Address": leaf.underlay_address, "Remote Hostname": leaf.hostname, "Remote Interface": leaf_interface}
            spine.point_to_point_neighbor_info.append(neighbor_info)

            #Update leaf with spine neighbor info
            leaf.spine_connection_info[i+1]["remote"]["Hostname"] = spine.hostname

            if leaf.bgp_neighbor_info is None:
                leaf.bgp_neighbor_info = {}
            if spine.asn not in list(leaf.bgp_neighbor_info):
                leaf.bgp_neighbor_info[spine.asn] = {}
                leaf.bgp_neighbor_info[spine.asn]["underlay"] = [spine_interface_address]
                leaf.bgp_neighbor_info[spine.asn]["overlay"] = [spine.underlay_address]
            else:
                leaf.bgp_neighbor_info[spine.asn]["underlay"].append(spine_interface_address)
                leaf.bgp_neighbor_info[spine.asn]["overlay"].append(spine.underlay_address)
            #Update VTEP list
            if leaf.overlay_address.split("/")[0] not in vtep_peers:
                vtep_peers.append(leaf.overlay_address.split("/")[0])
    
    #Update leafs' mlag_peer_mgmt_address field (important for assigning MLAG Vlan SVI)
    for l1 in leafs:
        for l2 in leafs:
            if l1.mlag_peer == l2.hostname:
                l1.mlag_peer_mgmt_address = l2.mgmt_address
                break
    logger.info("Successfully parsed spreadsheet")

    logger.info("Logging into CVP")
    cvp_addresses = global_options["CVP"]["CVP Addresses"]
    try:
        cvp = CvpClient()
        cvp.connect(cvp_addresses, username, password)
    except CvpClientError as e:
        logger.error(str(e))
        logger.info("FAILURE: Failed to log into CVP")
        return
    logger.info("Successfully logged into CVP")

    if int(option) == 1:
        #Configure a layer 3 leaf spine based on inputs in spreadsheet
        # check = input("WARNING: The program is using the Excel spreadsheet as a source of truth. Configurations created will only take into account what is present in spreadsheet. Existing configurations may be overwritten by what is produced from running this script.  Do you wish to continue? (yes/no)")
        # if not re.match(r'(?i)y|ye|yes', check):
        #     sys.exit(0)

        #Get telemetry statement
        #Get telemetry statement
        logger.info("Generating telemetry statement")
        telemetry_statement = get_telemetry_statement(cvp)
        if telemetry_statement is None:
            logger.error("FAILED to generate TerminAttr configuration")
            return
        logger.info("Successfully generated TerminAttr configuration")

        logger.info("Deploying Layer 3 Leaf Spine")
        logger.info("Starting leaf deployments")
        for leaf in leafs:
            deployL3LSLeaf(leaf)
        logger.info("Completed leaf deployments")

        logger.info("Starting spine deployments")
        for spine in spines:
            deployL3LSSpine(spine)
        logger.info("Completed spine deployments")

        if global_options["VXLAN"]["Vxlan Control Plane"] == "cvx":

            primary_cvx_address = global_options["CVX"]["Primary CVX IP Address"]
            secondary_cvx_address = global_options["CVX"]["Secondary CVX IP Address"]
            tertiary_cvx_address = global_options["CVX"]["Tertiary CVX IP Address"]
            cvx_addresses = [primary_cvx_address, secondary_cvx_address, tertiary_cvx_address]
            
            logger.info("Starting CVX Configurations")
            for cvx_address in cvx_addresses:
                configureCVXForVxlan(cvx_address)
            logger.info("Completed CVX Configurations")

    elif int(option) == 2:
        logger.info("Adding Vlans to Day 2 Target Devices")
        for device in day_2_target_devices:
            addVlansToLeaf(device)
        logger.info("Finished adding Vlans to Day 2 Target Devices")
    
    elif int(option) == 3:
        device_list = []
        for leaf in leafs:
            device_list.append(leaf)

        for spine in spines:
            device_list.append(spine)

        print("Starting Clean Up Configlets")
        for device in device_list:
            cleanUpDeviceConfiglets(device)

        print("Clean Up Configlets Finished")

    elif int(option) == 4:
        devices = []
        for leaf in leafs:
            devices.append(leaf)
        for spine in spines:
            devices.append(spine)
        for device in devices:
            try:
                task_ids = reset_device(cvp, device.serial_number)
                if execute_tasks == True:
                    for task_id in task_ids:
                        try:
                            cvp.api.execute_task(task_id)
                            print("Executed {}".format(task_id))
                        except Exception as e:
                            print("Error executing tasks related to {}".format(leaf.hostname))
                            print("Error:", e)
                    # delete_configlets(cvp, switch.fqdn)
            except:
                continue

    elif int(option) == 5:
        devices = []
        for leaf in leafs:
            delete_configlets(cvp, leaf.serial_number)
        for spine in spines:
            delete_configlets(cvp, spine.serial_number)

    #Playground
    elif int(option) == 8:
        pass
    #Pre-Deployment Check
    elif int(option) == 99:
        #Check containers exist in CVP
        logger.info("Checking for containers listed in the spreadsheet that are not in CVP...")
        containers = cvp.api.get_containers()["data"]
        container_names = [container['name'] for container in containers]
        containers_missing = False
        for leaf in leafs:
            if leaf.container_name not in container_names:
                logger.error("Leaf {}'s Container {} does not exist in CVP".format(leaf.hostname, leaf.container_name))
                containers_missing = True
        for spine in spines:
            if spine.container_name not in container_names:
                logger.error("Spine {}'s Container {} does not exist in CVP".format(spine.hostname, leaf.container_name))
                containers_missing = True
        if containers_missing is True:
            logger.error("FAILED container check")
        else:
            logger.info("SUCCESS: All containers in spreadsheet found in CVP")

        #Check switches exist in CVP
        switches_not_in_inventory = []
        switch_dicts = []
        logger.info("Checking for switches in the spreadsheet that are not in CVP's inventory...")
        for leaf in leafs:
            device_dict =  cvp.api.get_device_by_serial_number(leaf.serial_number)
            if device_dict != {}:
                switch_dicts.append(device_dict)
            else:
                switches_not_in_inventory.append(leaf)
        for spine in spines:
            device_dict =  cvp.api.get_device_by_serial_number(spine.serial_number)
            if device_dict != {}:
                switch_dicts.append(device_dict)
            else:
                switches_not_in_inventory.append(spine)

        #Check for switches in inventory
        if len(switches_not_in_inventory) > 0:
            logger.info("FAIL: Unable to find the following switches in CVP inventroy.  Please verify the serial numbers:")
            for switch in switches_not_in_inventory:
                logger.info("    {}--{}".format(switch.hostname, switch.serial_number))

        else:
            logger.info("SUCCESS: All switches in spreadsheet found in inventory\n")

        #Verify mlag neighbors are legit
        logger.info("Checking MLAG pairs...")
        mlag_error = False
        seen_mlag_pairs = {}
        hostnames_in_spreadsheet = [leaf.hostname for leaf in leafs]
        for leaf in leafs:
            if leaf.mlag_peer != "":
                if leaf.mlag_peer not in hostnames_in_spreadsheet:
                    logger.error("Unable to find {} in switch inventory".format(leaf.mlag_peer))
                    mlag_error = True
                elif leaf.mlag_peer == leaf.hostname:
                    logger.error("{}'s MLAG pair is itself. This is not allowed.".format(leaf.hostname))
                    mlag_error = True
                else:         
                    seen_mlag_pairs[leaf.hostname] = leaf.mlag_peer
        for k, v in seen_mlag_pairs.items():
            try:
                if seen_mlag_pairs[v] != k:
                    logger.error("{} has {} listed as its MLAG peer but {} does not have {} listed as its MLAG peer".format(k, v, v, k))
                    mlag_error = True
            except KeyError as e:
                mlag_error = True
        if mlag_error is True:
            logger.error("FAILED: invalid MLAG pairs exist in spreadsheet")
        else:
            logger.info("SUCCESS: All MLAG pairs appear to be valid")
        
        #Verify IP addresses used are valid
        logger.info("Checking if IP addresses are valid")
        ip_address_re = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}'
        seen_ip_addresses = {}
        for leaf in leafs:
            #Check management addresses
            # Validity check 
            if not re.match(ip_address_re, leaf.mgmt_address):
                logger.error("{}'s has an invalid Management IP address".format(leaf.hostname))
            #Duplicate check
            elif leaf.mgmt_address in seen_ip_addresses:
                logger.error("{} is using the same Management IP Address as {}".format(leaf.hostname, seen_ip_addresses[leaf.mgmt_address]))
            #All good
            else:
                seen_ip_addresses[leaf.mgmt_address] = leaf.hostname

            #Check loopback 0 addresses
            # Validity check 
            if not re.match(ip_address_re, leaf.underlay_address):
                logger.error("{}'s has an invalid Loopback0 IP address".format(leaf.hostname))
            #Duplicate check
            elif leaf.underlay_address in seen_ip_addresses:
                logger.error("{} is using the same Loopback0 IP Address as {}".format(leaf.hostname, seen_ip_addresses[leaf.underlay_address]))
            #All good
            else:
                seen_ip_addresses[leaf.underlay_address] = leaf.hostname

            #Check loopback1 addresses
            # Validity check 
            if not re.match(ip_address_re, leaf.overlay_address):
                logger.error("{}'s has an invalid Loopback1 IP address".format(leaf.hostname))

            #Check transit interface connections
            for connection_info in leaf.spine_connection_info.values():
                if connection_info["local"]["IP Address"] != "":
                    #check to see if local address is valid
                    if not re.match(ip_address_re, connection_info["local"]["IP Address"]):
                        logger.error("{}'s {} IP address is invalid.".format(leaf.hostname, connection_info["local"]["Interface"]))
                    
                    #Check to see if address is duplicate
                    if connection_info["local"]["IP Address"] in seen_ip_addresses:
                        logger.error("{} is already being used by {}".format(connection_info["local"]["IP Address"], seen_ip_addresses[connection_info["local"]["IP Address"]]))

                    seen_ip_addresses[ connection_info["local"]["IP Address"] ] = leaf.hostname

                    #check to see if remote address is valid
                    if not re.match(ip_address_re, connection_info["remote"]["IP Address"]):
                        logger.error("{}'s {} IP address is invalid.".format(connection_info["remote"]["Hostname"], connection_info["remote"]["Interface"]))

                    #Check to see if address is duplicate
                    if connection_info["remote"]["IP Address"] in seen_ip_addresses:
                        logger.error("{} is already being used by {}".format(connection_info["remote"]["IP Address"], seen_ip_addresses[connection_info["remote"]["IP Address"]]))
                    seen_ip_addresses[connection_info["remote"]["IP Address"]] = connection_info["remote"]["Hostname"]
                    #check to see if addresses are on same subnet
                    try:
                        if ipaddress.IPv4Interface(connection_info["local"]["IP Address"]).network != ipaddress.IPv4Interface(connection_info["remote"]["IP Address"]).network:
                            logger.error("{}'s transit connection to {} is using IP addresses on different subnets".format(
                                leaf.hostname, connection_info["remote"]["Hostname"]))
                    except:
                        continue

        for spine in spines:
            #Check management addresses
            # Validity check 
            if not re.match(ip_address_re, spine.mgmt_address):
                logger.error("{}'s has an invalid Management IP address".format(spine.hostname))
            #Duplicate check
            elif spine.mgmt_address in seen_ip_addresses:
                logger.error("{} is using the same Management IP Address as {}".format(spine.hostname, seen_ip_addresses[spine.mgmt_address]))
            #All good
            else:
                seen_ip_addresses[spine.mgmt_address] = spine.hostname

            #Check loopback 0 addresses
            # Validity check 
            if not re.match(ip_address_re, spine.underlay_address):
                logger.error("{}'s has an invalid Loopback0 IP address".format(spine.hostname))
            #Duplicate check
            elif spine.underlay_address in seen_ip_addresses:
                logger.error("{} is using the same Loopback0 IP Address as {}".format(spine.hostname, seen_ip_addresses[spine.underlay_address]))
            #All good
            else:
                seen_ip_addresses[spine.underlay_address] = spine.hostname
        logger.info("Finished checking switch IP addresses.")

        #Check BGP Neighbor details
        logger.info("Checking BPG neighbor details")
        for spine in spines:
            #Check accepted BGP ASNs
            beginning_asn, end_asn = int(spine.asn_range.split("-")[0].strip()), int(spine.asn_range.split("-")[1].strip())
            for leaf in leafs:
                # logger.info("{} < {} < {} : {}".format(beginning_asn, leaf.asn, end_asn, (int(leaf.asn) >= beginning_asn and int(leaf.asn) <= end_asn)))
                if not (int(leaf.asn) >= beginning_asn and int(leaf.asn) <= end_asn):
                    logger.error("{}'s ASN is outside of {}'s accepted ASN range".format(leaf.hostname, spine.hostname))
            
            #Check transit address range peering
            try:
                spine_transit_range = ipaddress.IPv4Network(spine.transit_ip_range)
                # logger.info("Created spine transit address listen range")
            except:
                logger.error("{} has an invalid value for Transit IP Range".format(spine.hostname))
                spine_transit_range = None
            if spine_transit_range is not None:
                for leaf in leafs:
                    for connection_info in leaf.spine_connection_info.values():
                        if connection_info["local"]["IP Address"] == "" or connection_info["remote"]["Hostname"] != spine.hostname:
                            continue
                        try:
                            ip_addr = ipaddress.IPv4Address(connection_info["local"]["IP Address"].split("/")[0])
                            # logger.info("Created IP address object of {}'s IP address {}".format(leaf.hostname, connection_info["local"]["IP Address"]))
                        except:
                            continue
                        # logger.debug("Is {} in {}? {}".format(str(ip_addr), spine.transit_ip_range, ip_addr in spine_transit_range.hosts()))
                        if ip_addr not in spine_transit_range.hosts():
                            logger.error("{}'s {}'s IP address ({}) is outside of {}'s BGP neighbor IP address listen range".format(leaf.hostname, connection_info["local"]["Interface"], connection_info["local"]["IP Address"], spine.hostname))
            #Check underlay loopback address range peering
            try:
                spine_underlay_address_range = ipaddress.IPv4Network(spine.underlay_loopback_ip_range)
            except:
                logger.error("{} has an invalid value for Transit IP Range".format(spine.hostname))
                spine_underlay_address_range = None
            if spine_underlay_address_range is not None:          
                for leaf in leafs:
                    try:
                        ip_addr = ipaddress.IPv4Address(leaf.underlay_address.split("/")[0])
                    except:
                        continue
                    if ip_addr not in spine_underlay_address_range.hosts():
                        logger.error("{}'s Loopback0 IP address ({}) is outside of {}'s BGP neighbor IP address listen range".format(leaf.hostname, leaf.underlay_address, spine.hostname))

        logger.info("Finished checking BPG neighbor details")


        #Verify that all chipsets are accounted for
        logger.info("Checking to see that all chipsets are accounted for...")
        chipset_check(switch_dicts, logger)

        logger.info("Finished pre-deployment check")

#########################################################################################################
#########################################################################################################
#########################################################################################################

def main():
    global execute_tasks
    cherrypy.quickstart(Handler(),'/',config = config)


if __name__ == "__main__":
    main()
