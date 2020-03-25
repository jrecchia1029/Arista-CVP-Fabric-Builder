from cvprac.cvp_client import CvpClient
#Disables no certificate CVP warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json


def updateInCVP(cvp, name, config, serial_number, apply=True):
    '''
    Args:
        name (str) -> name of the configlet
        config (str) -> content of configlet
        serial_number (str) -> device serial number
    Returns list of taskIds if any [1, 21]
    '''
    #Attempt to get config
    try:
        configlet_exists = cvp.api.get_configlet_by_name(name)
    except:
        print ("Configlet {} doesn't exist".format(name))
        configlet_exists = None
    #get device information from CVP
    device_dict = cvp.api.get_device_by_serial_number(serial_number)

    #initialize tasks variable
    task_ids = []
    tasks = None
    
    #Configlet does not exist
    if configlet_exists is None:
        #add new configlet to CVP
        configlet = cvp.api.add_configlet(name, config)
        print ("Added Configlet {} to CVP".format(name))
        #get newly created configlet
        new_configlet = cvp.api.get_configlet_by_name(name)

        if apply==True:
            #Create list of configlets to apply 
            configlets_to_apply = []
            #Add configlet to list of configlets to apply
            configlets_to_apply.append(new_configlet)

            #apply configlet to device
            tasks = cvp.api.apply_configlets_to_device("Generated by deployment script", device_dict,  configlets_to_apply)

    else:
        #configlet already exists

        #check if config is in sync
        # if checkIfDeviceInSync(device_dict) != True:
        #     #If device is not in sync return None
        #     return None

        #update existing configlet
        key = configlet_exists["key"]
        tasks = cvp.api.update_configlet(config, key, name, wait_task_ids=True)
        print ("Modified Configlet {} in CVP".format(name))

        if apply == True:

            try:
                if "taskIds" in list(tasks):
                    # print "Returning tasks for configlet {}".format(name)
                    task_ids = tasks["taskIds"]
            except:
                pass

            updated_configlet = cvp.api.get_configlet_by_name(name)
            configlets_already_applied = cvp.api.get_configlets_by_netelement_id(device_dict["key"])["configletList"]
            names_of_configlets_already_applied = []
            for configlet in configlets_already_applied:
                names_of_configlets_already_applied.append(configlet["name"])

            if updated_configlet["name"] not in names_of_configlets_already_applied:
                # print "Configlet {} is not applied".format(updated_configlet["name"])
                # print "Applying {} to {}".format(updated_configlet["name"], device_dict["hostname"])
                tasks = cvp.api.apply_configlets_to_device("Generated by deployment script", device_dict,  [updated_configlet])
                print ("Reapplied configlet to device")

    # return tasks
    if len(task_ids) > 0:
        try:
            tasks = tasks["data"]
            if "taskIds" in list(tasks):
                # print "Returning tasks for configlet {}".format(name)
                for task in tasks["taskIds"]:
                    if task not in task_ids:
                        task_ids.append(task)
                print ("task_ids:", task_ids)
                return task_ids
            else:
                # print "No tasks to return for configlet {}".format(name)
                print ("task_ids:", task_ids)
                return task_ids
        except:
            print ("task_ids:", task_ids)
            return task_ids
    else:
        try:
            tasks = tasks["data"]
            if "taskIds" in list(tasks):
                # print "Returning tasks for configlet {}".format(name)
                print ("task_ids:", task_ids)
                return tasks["taskIds"]
            else:
                # print "No tasks to return for configlet {}".format(name)
                print ("task_ids:", task_ids)
                return []
        except:
            return []

def moveDeviceToContainer(cvp, device_fqdn, container_name):
    try:
        container = cvp.api.get_container_by_name(container_name)
    except:
        print ("Could not find a valid container named {}".format(container_name))
        return
    try:
        device = cvp.api.get_device_by_name(device_fqdn)
    except:
        print ("Could not find a valid device named {}".format(device_fqdn))
        return

    tasks = cvp.api.move_device_to_container("Done by program", device, container)

    if "taskIds" in list(tasks["data"]):
        task_ids = tasks["data"]["taskIds"]
        for task_id in task_ids:
            cvp.api.execute_task(task_id)



def getReconcileConfiglet(cvp, device_fqdn, subject_configlet_name):
    '''
    '''
    device_dict = cvp.api.get_device_by_name(device_fqdn)
    #Get details for configlet that is going to be added or modified
    subject_configlet = cvp.api.get_configlet_by_name(subject_configlet_name)
    configlet_list = [] #list of all of the keys of configlets that are already applied to the device
    configlets_already_applied = cvp.api.get_configlets_by_netelement_id(device_dict["key"])
    for configlet in configlets_already_applied["configletList"]:
        configlet_list.append(configlet["key"])

    #Generate reconcile configlet
    target_configlets = configlet_list #list of all of the keys of configlets that will be applied to device
    
    #If the configlet is being newly applied to the device
    if subject_configlet["key"] not in configlet_list:
        #If the device already has a reconciled configlet applied
        if len(target_configlets) > 0 and cvp.api.get_configlet_by_id(target_configlets[len(target_configlets)-1])["reconciled"] == True:
                target_configlets.insert(-1, subject_configlet["key"])
        else:
            target_configlets.append(subject_configlet["key"])

    #Get reconcile information
    reconcile_info = cvp.api.validate_configlets_for_device(device_dict["key"], target_configlets)

    #set tasks variable
    tasks = None
    #Get the current reconciled configlet
    current_reconciled_configlet = getCurrentReconcileConfiglet(cvp, device_fqdn)
    #If you need to reconcile
    if reconcile_info["reconcile"] > 0:
        #if there is not already a reconciled configlet
        if current_reconciled_configlet is None:
            #Create, add, and get reconcile configlet
            #Get info from reconcile_info
            reconcile_config_info = reconcile_info["reconciledConfig"]
            #add reconciled configlet to cvp
            reconciled_config = cvp.api.add_configlet(reconcile_config_info["name"], reconcile_config_info["config"])
            reconciled_configlet = reconciled_config["data"][0]
            #mark as reconciled
            cvp.api.update_configlet(reconciled_config["config"], reconciled_config["key"], reconciled_configlet["name"], reconciled=True)
            reconciled_config = cvp.api.get_configlet_by_key(reconciled_config["key"])
        #If a reconciled configlet already exists
        else:
            #Get existing reconcile configlet and update
            current_reconciled_configlet["config"] = reconcile_info["reconciledConfig"]["config"]
            cvp.api.update_configlet(current_reconciled_configlet["key"], current_reconciled_configlet["name"], current_reconciled_configlet["config"], wait_task_ids=True)
            reconciled_config = cvp.api.get_configlet_by_key(reconciled_config["key"])

        #Verify that a reconcile configlet has been created
        print( cvp.api.get_temp_session_reconciled_configlets(device_dict["key"]))

    return reconciled_config
    

def getCurrentReconcileConfiglet(cvp, device_fqdn):
    device_dict = cvp.api.get_device_by_name(device_fqdn)
    configlets_already_applied = cvp.api.get_configlets_by_netelement_id(device_dict["key"])

    for configlet in configlets_already_applied["configletList"]:
        if configlet["reconciled"] == True:
            return configlet
    return None

def checkIfDeviceInSync(cvp, device_dict):
    '''
    Returns True if device is in sync and False if it not in sync
    '''
    compliance_code_dictionary = {
        "0000": True,
        "0001": False,
        "0002": True,
        "0003": False,
        "0004": True,
        "0005": False,
        "0006": True,
        "0007": True,
        "0008": False,
        "0009": False,
        "0010": True,
        "0011": False
    }
    device_cc = device_dict["complianceCode"]
    # device_cc = cvp.api.checkCompliance(device_dict["key"], "netelement")["complianceCode"]
    return compliance_code_dictionary[device_cc]

def cleanUpConfiglets(cvp, device_serial_number, category="Config"):
    '''
        category options are 'Management' and 'Config'
    '''
    #get device information from CVP
    device_dict = cvp.api.get_device_by_name(device_serial_number)
    # print "Device"
    # print json.dumps(device_dict)
    # print "\n\n"
    device_id = device_dict["systemMacAddress"]
    configlets = cvp.api.get_configlets_by_device_id(device_id)
    # print "Configlets"
    # print json.dumps(configlets)
    # print "\n\n"

    #Get list of configlets to consolidate
    if category == "Config":
        names_of_configlets_to_consolidate = ["_MLAG", "_IP_Interfaces","_BGP_Underlay", "_BGP_Overlay", "_IBGP_Between_MLAGs", 
                                        "_Vxlan_Data_Plane", "_Vxlan_Control_Plane", "_VRFs", "_Vlans", "_Config"]
    elif "category" == "Management":
        names_of_configlets_to_consolidate = ["_MGMT"]

    for i, name in enumerate(names_of_configlets_to_consolidate):
        names_of_configlets_to_consolidate[i] = device_dict["hostname"] + name

    #Configlet dictionaries of configlets that will be consolidated
    configlets_to_remove = []
    #keys of configlets we'll pretend are applied to a device when we generate a reconcile config 
    configlet_keys = []
    for configlet in configlets:
        if configlet["netElementCount"] == 1 and configlet["name"] in names_of_configlets_to_consolidate:
            configlets_to_remove.append(configlet)
        else:
            configlet_keys.append(configlet["key"])

    #Generate consolidated configlet
    print ("Generating consolidated configlet")
    validate_response = cvp.api.validate_configlets_for_device(device_id, configlet_keys,
                                       page_type='viewConfig')
    config = validate_response["reconciledConfig"]["config"]
    print ("Generated consolidated configlet")

    #Remove Old Configlets
    print( "Removing configlets")
    tasks = cvp.api.remove_configlets_from_device("Generated by deployment program", device_dict, configlets_to_remove)
    print( "Tasks:", tasks)
    print ("Removed configlets")

    #Create and apply consolidated configlet
    if category == "Config":
        configlet_name = device_dict["hostname"] + "_Config"
    else:
        configlet_name = device_dict["hostname"] + "_MGMT"

    #Apply New Configlet
    print ("Applying new configlet")
    tasks =  updateInCVP(cvp, configlet_name, config, device_serial_number)
    print ("Applied new configlet")
    return tasks


def reset_device(cvp, serial_number, delete_configlets=True):
    #get device information from CVP
    device_dict = cvp.api.get_device_by_serial_number(serial_number)
    # print "Device"
    # print json.dumps(device_dict)
    # print "\n\n"
    device_id = device_dict["systemMacAddress"]
    configlets = cvp.api.get_configlets_by_device_id(device_id)
    # print "Configlets"
    # print json.dumps(configlets)
    # print "\n\n"


    names_of_configlets_to_remove = [" _MLAG", " _IP_Interfaces"," _BGP_Underlay", " _BGP_Overlay", " _IBGP_Between_MLAGs", 
                                        " _Vxlan_Data_Plane", " _Vxlan_Control_Plane", " _VRFs", " _Vlans", " _Config"]

    for i, name in enumerate(names_of_configlets_to_remove):
        names_of_configlets_to_remove[i] = device_dict["hostname"] + name

    #Configlet dictionaries of configlets that will be consolidated
    configlets_to_remove = []
    #keys of configlets we'll pretend are applied to a device when we generate a reconcile config 
    configlet_keys = []
    for configlet in configlets:
        if configlet["netElementCount"] == 1 and configlet["name"] in names_of_configlets_to_remove:
            configlets_to_remove.append(configlet)

    #Remove Old Configlets
    print ("Removing configlets")
    tasks = cvp.api.remove_configlets_from_device("Generated by deployment program", device_dict, configlets_to_remove)
    print ("Tasks:", tasks)
    print ("Removed configlets")


    #Apply New Configlet
    if delete_configlets == True:
        print ("Deleting old configlets")
        for configlet in configlets_to_remove:
            cvp.api.delete_configlet(configlet["name"], configlet["key"])
        print ("Deleted old configlets")
    
    try:
        tasks = tasks["data"]
        if "taskIds" in list(tasks):
            # print "Returning tasks for configlet {}".format(name)
            return tasks["taskIds"]
        else:
            # print "No tasks to return for configlet {}".format(name)
            return []
    except:
        return []

def delete_configlets(cvp, serial_number):
    device_dict = cvp.api.get_device_by_serial_number(serial_number)

    names_of_configlets_to_remove = ["_MLAG", "_IP_Interfaces","_BGP_Underlay", "_BGP_Overlay", "_IBGP_Between_MLAGs", 
                                        "_Vxlan_Data_Plane", "_Vxlan_Control_Plane", "_VRFs", "_Vlans", "_Config"]

    for i, name in enumerate(names_of_configlets_to_remove):
        names_of_configlets_to_remove[i] = device_dict["hostname"] + name

    for configlet_name in names_of_configlets_to_remove:
        try:
            configlet = cvp.api.get_configlet_by_name(configlet_name)
            if configlet is not None:
                cvp.api.delete_configlet(configlet["name"], configlet["key"])
        except KeyboardInterrupt:
            sys.exit()
        except:
            continue
    
    print( "Deleted configlets")