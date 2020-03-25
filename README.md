# Fabric Builder

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

First clone the repository to your local machine and navigate to the Arista-CVP-Fabric-Builder directory

```
git clone git@github.com:jrecchia1029/Arista-CVP-Fabric-Builder.git
cd Arista-CVP-Fabric-Builder/
```


### Prerequisites
- python3 is required to run the script
- The modules listed in the requirements.txt file need to be installed
```
pip install -r FabricBuilder/requirements.txt
```

### Navigate into the FabricBuilder directory

```
cd FabricBuilder
```

### Run the script using a version of python3

```
python main.py
```

### Navigate to http://127.0.0.1:8080

In a web browser, go to http://127.0.0.1:8080 to input the proper information and run the program.

Deploy leaf switches by editing the Leaf Info sheet.
- If a leaf switch listed in the sheet is in the undefined container in CVP, the script will build out  an entire configuration for the switch bbased on the values in the Leaf Info sheet and Global Variables sheet..
- If a leaf switch listed in the sheet is out of the undefined container in CVP, the script will not do anything to the leaf in CVP.

Deploy spines by editing the Spine Info sheet.
- If a spine switch listed in the sheet is in the undefined container in CVP, the script will build out an entire configuration for the switch based on the values in the Spine Info sheet and Global Variables sheet.
- If a spine switch listed in the sheet is out of the undefined container in CVP, the script will only modify the Spine's IP interface configlet to update the interface configlets to account for the new switches listed in the Leaf Info spreadsheet.  Note that if switches that had been present in the Leaf Info sheet from a previous deployment are absent during a subsequent script run of the Deploy L3LS function, the interfaces already present in the IP interfaces configlet will not be deleted or overwritten unless a new switch in the Leaf Info sheet connects to a spine switch via an interface  that is already being used in the configlet.  In this case, that interface will be overwritten with whatever is presently configured in the spreadsheet.

Adding Vlans
- To add vlans, add the proper switch info to the Day 2 Target Devices sheet.  These will be the switches the script adds the vlan configuration to.   Input the proper values in the Vlan sheet for the vlans you wish to add to the switches.  The script will create a vlan configlet based off the configuration filled out in the Global Variables sheet, Vlan sheet, and Day 2 Target Switches sheet.  Note that if switches that had been present in the Day 2 Target Switches sheet from a previous run of the Add Vlans function, the vlans already configured in the Vlan configlet will not be deleted or overwritten unless a new vlan in the Vlans sheet is already being used in the configlet.  In this case, the configuration for that vlan will be overwritten with whatever is presently configured in the spreadsheet.

Pre-Check
- Performs basic checks to see if anything may fail during the script execution.
- More details to follow
