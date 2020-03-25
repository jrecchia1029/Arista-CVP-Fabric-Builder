from collections import OrderedDict

class Spine():
    def __init__(self, serial_number, container_name, hostname, mgmt_address,
            mgmt_interface, asn, asn_range, underlay_address, transit_ip_range, underlay_loopback_ip_range, ecmp_paths, image_bundle):
        self.serial_number = serial_number
        self.container_name = container_name
        self.hostname = hostname
        self.mgmt_address = mgmt_address
        self.mgmt_interface = mgmt_interface
        self.asn = int(asn) if asn is not None else None
        self.asn_range = asn_range
        self.underlay_address = underlay_address
        self.transit_ip_range = transit_ip_range
        self.underlay_loopback_ip_range = underlay_loopback_ip_range
        self.ecmp_paths = int(ecmp_paths) if ecmp_paths is not None else None
        self.point_to_point_neighbor_info = None
        self.image_bundle = image_bundle

    def prep_leaf_connection_info_for_configlet_builder(self):
        connection_info = OrderedDict()
        for info in self.point_to_point_neighbor_info:
            if info["Local Interface"] is not None and info["Local Interface"] != "":
                connection_details = {}
                connection_details["IP Address"] = info["Local IP Address"]
                connection_details["Remote Interface"] = info["Remote Interface"]
                connection_details["Remote Hostname"] = info["Remote Hostname"]
                connection_info[info["Local Interface"]] = connection_details
        return connection_info
        
    def prep_bgp_connection_info_for_configlet_builder(self):
        bgp_info = OrderedDict()
        for info in self.point_to_point_neighbor_info:
            if info["Neighbor ASN"] not in list(bgp_info):
                bgp_info[info["Neighbor ASN"]] = [info["Neighbor IP Address"].split("/")[0]]
            else:
                bgp_info[info["Neighbor ASN"]].append(info["Neighbor IP Address"].split("/")[0])
        return bgp_info

    def prep_evpn_connection_info_for_configlet_builder(self):
        bgp_info = OrderedDict()
        for info in self.point_to_point_neighbor_info:
            if info["Neighbor ASN"] not in list(bgp_info):
                bgp_info[info["Neighbor ASN"]] = [info["Neighbor EVPN Transit Address"].split("/")[0]]
            else:
                bgp_info[info["Neighbor ASN"]].append(info["Neighbor EVPN Transit Address"].split("/")[0])
        return bgp_info