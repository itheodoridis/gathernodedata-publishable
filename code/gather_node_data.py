#!/usr/bin/env python
from nornir_nauto_noc_utils import get_the_macs_addresses,get_the_arps,enrich_node_mac_data
from noc_net_utils import node_resolve
from nautobot_credentials import nautobot_url, nautobot_token
from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_credentials import bucket,org,token,url
from influxdb_client import InfluxDBClient, Point, WriteOptions
import time
import ipdb

def main():
    #TODO - run the logger in the main function so the functions can be transfered to a separate file (library)
    filter_param_dict = {"status": "active", "site" : ["site1", "site2", "site3"], "role" : "ac-access-switch", 
                "has_primary_ip": True}
    mac_list = get_the_macs_addresses(nautobot_url,nautobot_token,filter_param_dict,SAVE_RESULTS=False,DEBUG_DATA=False,DATA_LOGGING=False)
    if mac_list == None:
        print("no mac addresses were collected")
        return()
    
    filter_param_dict = {"status": "active", "site" : ["site1", "site2", "site3"], "role" : "ac-distribution-switch", 
                "has_primary_ip": True}
    arp_list = get_the_arps(nautobot_url,nautobot_token,filter_param_dict,SAVE_RESULTS=False,DEBUG_DATA=False,DATA_LOGGING=True)
    if arp_list == None:
        print("no arp entries were collected")
        return()

    resolved_list=node_resolve(arp_list)
    final_list = enrich_node_mac_data(resolved_list,mac_list,SAVE_RESULTS=True,DEBUG_DATA=False,DATA_LOGGING=True)
    if final_list == None:
        print("no resolved entries were collected")
    #ipdb.set_trace()
    client = InfluxDBClient(
        url=url,
        token=token,
        org=org,
        verify_ssl=False
    )
    write_api = client.write_api(write_options=SYNCHRONOUS)

    timestr = str(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    for record in final_list:
        #p = influxdb_client.Point("mac-address-access-network-attiki").tag("mac-address", record['mac_address']).field("temperature", 25.3)
        p = Point("mac-address-access-network"
            ).tag("switch_address",record["switch_address"]
            ).tag("switch_name",record["switch_name"]
            ).tag("port",record["port"]
            ).tag("mac-address",record['mac_address']
            ).tag("host_ip",record["host_ip"]
            ).tag("host_name",record["host_name"]
            ).tag("vlan",record["vlan"]
            ).field("switch_location",record["switch_location"]
            ).time(timestr)
        write_api.write(bucket=bucket, org=org, record=p)
    client.close()

    return()

if __name__ == "__main__":
    main()
