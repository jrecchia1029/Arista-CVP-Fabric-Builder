import sys
import ipaddress

class SignalHandler:
    """
    The object that will handle signals and stop the worker threads.
    """

    # #: The stop event that's shared by this handler and threads.
    # stopper = None

    # #: The pool of worker threads
    # workers = None

    def __init__(self, stopper, workers):
        self.stopper = stopper
        self.workers = workers

    def __call__(self, signum, frame):
        """
        This will be called by the python signal module

        https://docs.python.org/3/library/signal.html#signal.signal
        """
        print( "Called stopper")
        self.stopper.set()

        for worker in self.workers:
            print( worker.name)
            worker.join()

        sys.exit(0)

def updateTaskList(response_task_list, total_task_list):
    if response_task_list is not None:
        for tid in response_task_list:
            if str(tid) not in total_task_list:
                total_task_list.append(str(tid))
    return total_task_list

def printConfiglet(configlet_name, config):
    print("*"*70)
    print(configlet_name)
    print("*"*70)
    print(config)
    print("*"*70)

def cleanup_variable_values(global_options, logger):
    #Verify we have all keys:
    missing_key_flag = False
    global_variable_keys = {
        "GENERAL": ["Underlay Source Interface", "Overlay Source Interface", "NAT Loopback"],
        "MANAGEMENT": ["Default Gateway", "VRF", "VRF Route-Distinguisher"],
        "MLAG": ["Domain ID", "SVI Address Range", "Port-Channel Number", "Vlan", "Trunk Group Name", "Virtual Mac Address",
        "Dual Primary Detection Delay", "Dual Primary Detection Action", "Peer Address Heartbeat"],
        "IBGP Between MLAG Peers":["IBGP", "Peering SVI", "SVI Address Range", "Peer Group Name", "Maximum Routes", "Password"],
        "BGP": ["Underlay Peer Group Name", "Overlay Peer Group Name", "Route-Map Name", "Underlay Prefix List Name", "Loopback Prefix List Name",
        "BFD in Underlay", "BFD in Overlay", "Password", "Spine Peer Filter Name"],
        "VXLAN":["Vxlan Data Plane", "Vxlan Control Plane", "UDP Port"],
        "CVX":["Primary CVX IP Address", "Secondary CVX IP Address", "Tertiary CVX IP Address"],
        "EVPN":["Model"]
        }
    for primary_key, secondary_keys in global_variable_keys.items():
        if primary_key not in global_options.keys():
            logger.error("Unable to find primary key  '{}' in 'Global Variables L3LS' sheet.".format(primary_key))
            missing_key_flag = True
            continue
        for secondary_key in secondary_keys:
            if secondary_key not in global_options[primary_key].keys():
                logger.error("Unable to find secondary key '{}' in 'Global Variables L3LS' sheet.".format(secondary_key))
                missing_key_flag = True
    if missing_key_flag is True:
        return None
    global_options["GENERAL"]["Underlay Source Interface"] = global_options["GENERAL"]["Underlay Source Interface"].replace(" ", "")
    global_options["GENERAL"]["Overlay Source Interface"] = global_options["GENERAL"]["Overlay Source Interface"].replace(" ", "")
    global_options["GENERAL"]["NAT Loopback"] =  global_options["GENERAL"]["NAT Loopback"].replace(" ", "")
    return global_options

def get_common_subnet(ip_addresses):
    '''
    Given a list of ip addresses, return the most specific subnet
    '''
    subnet = None
    ip_addresses = [ip_address.split("/")[0] for ip_address in ip_addresses]
    for i, ip_address in enumerate(ip_addresses):
        ip_addresses[i] = ''.join([bin(int(x)+256)[3:] for x in ip_address.split('.')])
        # print(ip_addresses[i])
    if len(ip_addresses) > 0:
        match = True
        subnet_mask = 0
        prefix = ""
        for char in ip_addresses[0]:
            prefix += char
            for ip_address in ip_addresses:
                if ip_address[subnet_mask] != char:
                    match = False
                    break
            if match == True:
                subnet_mask += 1
            else:
                prefix = prefix[:-1]
                break
        network_address = prefix
        for i in range(32-len(prefix)):
            network_address += "0"
        # print(network_address)
        network_address = '.'.join(str(int(network_address[i:i+8], 2)) for i in range(0, 32, 8)) + "/" + str(subnet_mask)
    return network_address if network_address is not None else None


def chipset_check(switch_device_dict, logger):
    #Run chipset support check
    from SwitchHelpers.chips import chipModelInfo
    from SwitchHelpers.models import switchModelInfo

    switch_models_missing_from_switch_model_dict = []
    chipsets_missing_from_chipset_dict = []
    for switch in switch_device_dict:
        modelName = switch["modelName"]
        #If switch model is included in dictionary of switch models
        if modelName in list(switchModelInfo):
            chipset = switchModelInfo[modelName]["chipset"]
            #If chipset is included in dictionary of chipsets
            if chipset in list(chipModelInfo):
                continue
            #If chipset is NOT included in dictionary of chipsets
            else:
                chipsets_missing_from_chipset_dict.append(chipset)
        #If switch model is NOT included in dictionary of switch models
        else:
            switch_models_missing_from_switch_model_dict.append(modelName)

    if len(switch_models_missing_from_switch_model_dict) > 0 or len(chipsets_missing_from_chipset_dict) > 0:
        logger.warning("WARNING: FAILED CHIPSET TEST")

        if len(switch_models_missing_from_switch_model_dict) > 0:
            warning_message = ""
            warning_message += "Info for the following switch models will need to be added to script:"
            for model in switch_models_missing_from_switch_model_dict:
                logger.warning("  {}".format(model))
            print("\n")

        if len(chipsets_missing_from_chipset_dict) > 0:
            logger.warning("Info for the following chipsets will need to be added to script:")
            for chipset in chipsets_missing_from_chipset_dict:
                logger.warning("  {}".format(chipset))
            print( "\n")
    else:
        logger.info("SUCCESS: PASSED CHIPSET CHECK\n")

if __name__ == "__main__":
    print(get_common_subnet(["172.16.200.1/31", "172.16.200.3/31", "172.1.255.255/31"]))