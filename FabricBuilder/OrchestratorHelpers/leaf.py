from collections import OrderedDict

class Leaf():
    def __init__(self, serial_number, container_name, hostname, mgmt_address, mgmt_interface,
            mlag_peer, mlag_interfaces, asn, underlay_address, overlay_address, spine_connection_info, nat_id, image_bundle
            ):
        self.serial_number = serial_number
        self.container_name = container_name
        self.hostname = hostname
        self.mgmt_address = mgmt_address
        self.mgmt_interface = mgmt_interface
        self.mlag_peer = mlag_peer
        self.mlag_peer_mgmt_address = None
        self.mlag_interfaces = mlag_interfaces
        self.asn = int(asn) if asn is not None else None
        self.bgp_neighbor_info = None
        self.underlay_address = underlay_address
        self.overlay_address = overlay_address
        self.spine_connection_info = spine_connection_info
        self.nat_id = nat_id
        self.image_bundle = image_bundle

    def prep_spine_connection_info_for_configlet_builder(self):
        connection_info = OrderedDict()
        for i, info in enumerate(self.spine_connection_info.values()):
            if info["local"]["Interface"] is not None and info["local"]["Interface"] != "":
                connection_details = {}
                connection_details["IP Address"] = info["local"]["IP Address"]
                connection_details["Remote Interface"] = info["remote"]["Interface"]
                connection_details["Remote Hostname"] = info["remote"]["Hostname"]
                connection_info[info["local"]["Interface"]] = connection_details
        return connection_info
        
    def prep_bgp_underlay_neighbor_info(self):
        bgp_underlay_info = OrderedDict()
        for asn, planes in self.bgp_neighbor_info.items():
            bgp_underlay_info[asn] = [address.split("/")[0] for address in planes["underlay"]]
        return bgp_underlay_info

    def prep_bgp_overlay_neighbor_info(self):
        bgp_underlay_info = OrderedDict()
        for asn, planes in self.bgp_neighbor_info.items():
            bgp_underlay_info[asn] = [address.split("/")[0] for address in planes["overlay"]]
        return bgp_underlay_info