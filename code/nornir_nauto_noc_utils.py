#!/usr/bin/env python
from platform import platform
from nornir import InitNornir
from nornir.core.exceptions import NornirSubTaskError
from nornir_netmiko.tasks import netmiko_send_command, netmiko_send_config
from nornir_utils.plugins.functions import print_result
from nornir.core.inventory import ConnectionOptions
from nornir.core.filter import F
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetMikoTimeoutException, NetmikoBaseException
from paramiko import AuthenticationException
from paramiko.ssh_exception import SSHException
#TODO Add timeout exception
import requests
import time
import pprint
import logging
from rich.console import Console
from rich.table import Table
from device_credentials import dev_username, dev_password
from noc_net_utils import save_the_list,print_the_list
import netutils
import ipdb

#logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',
#                    filename='get_the_macs.log', level=logging.INFO)

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger('nornir')
Global_DATA_LOGGING = False
Global_DEBUG_DATA = False

def reset_connection(host):
    """Remove host from the Nornir connection table."""
    try:
        host.close_connections()
    except ValueError:
        pass

'''This function runs a show command and returns data in the form of a result object'''
def get_show_data(task,show_command:str):
    time.sleep(2)
    try:
        task.host.get_connection("netmiko", configuration=task.nornir.config)
        show_data = task.run(name="show_me_your_data",
                                    task=netmiko_send_command,
                                    command_string=show_command, 
                                    use_textfsm=True, enable=True)
        task.host.close_connection("netmiko")
    except NornirSubTaskError as e:
        # Check type of exception
        if (isinstance(e.result.exception, NetmikoAuthenticationException)) or (isinstance(e.result.exception, AuthenticationException)):
            # Remove the failed result
            task.results.pop()
            reset_connection(task.host)
            # Try again
            time.sleep(1)
            task.host.get_connection("netmiko", configuration=task.nornir.config)
            show_data = task.run(name="show_me_your_data",
                                    task=netmiko_send_command,
                                    command_string=show_command, 
                                    use_textfsm=True, enable=True)
            task.host.close_connection("netmiko")
    return(show_data)

'''This function runs a show command and returns data in the form of a result object'''
def get_show_data_multiple(task,show_commands:list[str]):
    time.sleep(2)
    command_results = {}
    try:
        task.host.get_connection("netmiko", configuration=task.nornir.config)
        for show_command in show_commands:
            show_data = task.run(name="show_me_your_data",
                                        task=netmiko_send_command,
                                        command_string=show_command, 
                                        use_textfsm=True, enable=True)
            command_results[show_command]=show_data
        task.host.close_connection("netmiko")
    except NornirSubTaskError as e:
        # Check type of exception
        if (isinstance(e.result.exception, NetmikoAuthenticationException)) or (isinstance(e.result.exception, AuthenticationException)):
            # Remove the failed result
            task.results.pop()
            reset_connection(task.host)
            # Try again
            time.sleep(1)
            task.host.get_connection("netmiko", configuration=task.nornir.config)
            for show_command in show_commands:
                show_data = task.run(name="show_me_your_data",
                                        task=netmiko_send_command,
                                        command_string=show_command, 
                                        use_textfsm=True, enable=True)
                command_results[show_command]=show_data
            task.host.close_connection("netmiko")
    return(command_results)

#TODO - The process of adding mac addresses to the list and adding to the table needs to be separated
#TODO - A separate list of dicts for host data needs to be created. Rows to be derived from it.
def add_entries(run,run_result,collect_function):
    #process results
    host_list = []
    for each_result in run_result:
        (node_name,node_address,node_location)=get_host_inv_data(run=run,each_result=each_result)
        check = print_check_node_results(run_result=run_result,each_result=each_result,node_name=node_name,node_address=node_address)
        if check == True:
            continue
        try:
            entries_table=run_result[each_result].result.result
            check_empty_list = check_empty_entries_list(entries_table)
            if check_empty_list == True:
                continue
                #TODO - we should add a continue statement if there are no macs

            for line in entries_table:
                host_dict=collect_function(line,node_name,node_address,node_location)
                if host_dict == None:
                    continue
                host_list.append(host_dict)

        except:
            print_bad_node(node_name=node_name,node_address=node_address)

    check_list = check_empty_entries_list(host_list)
    if check_list == False:
        return host_list
    else:
        return None

def add_entries_multiple(run,run_result,collect_all_function):

    #This loop itterates over hosts
    host_list=[]
    for each_result in run_result:
        #Get host data and check host results
        (node_name,node_address,node_location)=get_host_inv_data(run=run,each_result=each_result)
        check = print_check_node_results(run_result=run_result,each_result=each_result,node_name=node_name,node_address=node_address)
        if check == True:
            continue
        try:
            '''Time to get results for this host. The following accesses data for this host'''
            node_results = run_result[each_result].result
            '''At this point this needs to get directed in a special function depending on the process. 
            For mac addresses it needs to be aware of the two commands, 
            show mac address-table and show cdp neighbors. Itterating over the keys will not work.'''
            entries_list = collect_all_function(node_results=node_results,node_name=node_name,node_address=node_address,node_location=node_location)
            if entries_list == None:
                continue

            host_list.extend(entries_list)
        except:
            print_bad_node(node_name=node_name,node_address=node_address)
        
    check_list = check_empty_entries_list(host_list)
    if check_list == False:
        return host_list
    else:
        return None

def get_host_inv_data(run,each_result):
    host_name = each_result
    host_address = run.inventory.hosts[each_result].dict()['hostname']
    host_location = run.inventory.hosts[each_result].dict()['data']['pynautobot_dictionary']['site']['name']
    return host_name,host_address,host_location

#Returns true if there is a failure in the result
def print_check_node_results(run_result,each_result,node_name,node_address):
    global Global_DATA_LOGGING
    global Global_DEBUG_DATA
    if Global_DEBUG_DATA == True:
        print(f"switch: {node_name} ip address: {node_address}")
    if run_result[each_result].failed:
        if Global_DEBUG_DATA == True:
            print(run_result[each_result].exception)
        if Global_DATA_LOGGING == True:
            logger.info(f" - Failure: {run_result[each_result].exception}")
        return True
    else:
        return False

def print_bad_node(node_name,node_address):
    global Global_DATA_LOGGING
    global Global_DEBUG_DATA
    if Global_DEBUG_DATA == True:
        print("something wrong with host", node_name)
    if Global_DATA_LOGGING == True:
        logger.info(f"- Something wrong with host {node_name} ip-address:{node_address}")
    return

# Returns true if there are no list entries
def check_empty_entries_list(entries_list):
    global Global_DEBUG_DATA
    if Global_DEBUG_DATA == True:
        print(f"Total entries: {len(entries_list)}")
    if not len(entries_list):
        if Global_DEBUG_DATA == True:
            print("no entries")
        return True
    else:
        return False

def collect_all_macs(node_results,node_name,node_address,node_location):
    mac_table_list = node_results["show mac address-table"].result
    cdp_nei_list = node_results["show cdp neighbors"].result
    final_mac_table_list = []
    for line in mac_table_list:
        host_dict=collect_mac(line,node_name,node_address,node_location)
        if host_dict == None:
            continue
        if host_dict["port"] in [cdp_nei["local_interface"].replace(" ","").replace("Gig","Gi").replace("Fas","Fa") for cdp_nei in cdp_nei_list]:
            continue
        final_mac_table_list.append(host_dict)
    check_list = check_empty_entries_list(final_mac_table_list)
    if not check_list:
        return final_mac_table_list
    else:
        return None

def collect_mac(line,switch_name,switch_address,switch_location):
    #if ((line["type"] == "STATIC") and ('CPU' not in line['destination_port'][0])):
    if ('CPU' not in line['destination_port'][0]):
        host_dict = dict()
        host_dict['mac_address'] = line['destination_address']
        host_dict['vlan'] = line['vlan']
        host_dict['port'] = line['destination_port'][0]
        host_dict['switch_name'] = switch_name
        host_dict['switch_address'] = switch_address
        host_dict['switch_location'] = switch_location
        return host_dict
    else:
        return None

def collect_arp(line,node_name,node_address,node_location):
    if (('Vlan' in line['interface'])):
        host_dict = dict()
        host_dict['mac_address'] = line['mac']
        host_dict['host_ip'] = line['address']
        host_dict['vlan'] = line['interface']
        host_dict['switch_name'] = node_name
        host_dict['switch_address'] = node_address
        host_dict['switch_location'] = node_location
        return host_dict
    else:
        return None

'''This function is not used'''
def collect_cdp_interfaces(line,node_name,node_address,node_location):
    host_dict = dict()
    host_dict['port'] = line['local_port']
    host_dict['switch_name'] = node_name
    host_dict['switch_address'] = node_address
    host_dict['location'] = node_location
    return host_dict

'''Gets the macs on a list to be saved and prints the macs on screen'''
#TODO - Change with return None for failure
def get_the_macs_addresses(nautobot_url,nautobot_token,filter_param_dict,SAVE_RESULTS=False,DEBUG_DATA=False,DATA_LOGGING=False):
    global Global_DATA_LOGGING
    global Global_DEBUG_DATA
    Global_DATA_LOGGING = DATA_LOGGING
    Global_DEBUG_DATA = DEBUG_DATA

    nautobot_ssl_verify = False
    #define inventory
    nr = initialize_inventory(nautobot_url,nautobot_token,filter_param_dict,nautobot_ssl_verify)

    if DATA_LOGGING==True:
        logger.info("\nSTART")
        logger.info("- Initiating Nornir")

    run_platform = 'cisco_ios'
    run_workers = 40
    run_task = get_show_data_multiple
    show_commands = ["show mac address-table","show cdp neighbors"]

    if DATA_LOGGING==True:
        logger.info(" - Starting Parallel SSH Tasks")
    ssh_run = nr.filter(F(platform="cisco-ios") | F(platform="cisco-ios-xe"))

    ssh_results = do_the_run_multiple(ssh_run,run_task,run_platform,run_workers,dev_username,dev_password,show_commands)
    #TODO - Separate the filtering from the run. Same process for both runs if possible

    if DATA_LOGGING==True:
        logger.info(" - Closed SSH Connections")
    
    #check for failures in ssh switches
    if (DEBUG_DATA == True) and (ssh_results.failed):
        print(f"SSH Failure exists: {ssh_results.failed}\nFailed SSH Hosts:")
        pprint.pprint(ssh_results.failed_hosts)
    if DATA_LOGGING==True:
        logger.info(f" - SSH Failure exists: {ssh_results.failed}")
        logger.info(" - Adding macs from ssh run to list")

    host_list = []
    ssh_host_list = add_entries_multiple(run=ssh_run,run_result=ssh_results,collect_all_function=collect_all_macs)

    #TODO - Create debug and logging for this
    if ssh_host_list != None:
        host_list.extend(ssh_host_list)

    telnet_run = nr.filter(platform="cisco-ios-telnet")
    run_platform = 'cisco_ios_telnet'
    run_workers = 4

    telnet_results = do_the_run_multiple(telnet_run,run_task,run_platform,run_workers,dev_username,dev_password,show_commands)
    if DATA_LOGGING == True:
        logger.info(" - Closed Telnet Connections")
        logger.info(f" - Telnet Failure exists: {telnet_results.failed}")
        logger.info(" - Adding macs from telnet run to list")
    
    #check for failures in telnet switches
    if (DEBUG_DATA==True) and (telnet_results.failed):
        print(f"Telnet Failure exists: {telnet_results.failed}\nFailed Telnet Hosts:")
        pprint.pprint(telnet_results.failed_hosts)

    #TODO - Create debug and logging for this
    telnet_host_list = add_entries_multiple(run=telnet_run,run_result=telnet_results,collect_all_function=collect_all_macs)
    if telnet_host_list != None:
        host_list.extend(telnet_host_list)

    #TODO - Create debug and logging for no macs
    if DATA_LOGGING == True:
        logger.info(" - All macs have been gathered.")

    #TODO - Create if to save only if there are macs to save
    if SAVE_RESULTS == True:
        logger.info(" - Writing macs in file")
        mac_list = create_entries_rows(host_list,create_mac_row)
        save_the_list(mac_list, "macs.txt")
        logger.info(" - File closed.\nEND")
    if DEBUG_DATA == True:
        create_mac_table(host_list)

    return(host_list)

#TODO - Change with return None for failure
def get_the_arps(nautobot_url,nautobot_token,filter_param_dict,SAVE_RESULTS=False,DEBUG_DATA=False,DATA_LOGGING=False):
    global Global_DATA_LOGGING
    global Global_DEBUG_DATA
    Global_DATA_LOGGING = DATA_LOGGING
    Global_DEBUG_DATA = DEBUG_DATA

    if DATA_LOGGING==True:
        logger.info("\nSTART")
        logger.info("- Initiating Nornir")

    nautobot_ssl_verify = False
    #define inventory
    nr = initialize_inventory(nautobot_url,nautobot_token,filter_param_dict,nautobot_ssl_verify)

    ssh_run = nr.filter(F(platform="cisco-ios") | F(platform="cisco-ios-xe"))
    run_platform = 'cisco_ios'
    run_workers = 40
    run_task = get_show_data
    show_command = "show ip arp"

    if DATA_LOGGING==True:
        logger.info(" - Starting Parallel SSH Tasks")

    ssh_result = do_the_run(ssh_run,run_task,run_platform,run_workers,dev_username,dev_password,show_command)
    #TODO - Separate the filtering from the run. Same process for both runs if possible

    if DATA_LOGGING==True:
        logger.info(" - Closed SSH Connections")
    
    #check for failures in ssh switches
    if (DEBUG_DATA == True) and (ssh_result.failed):
        print(f"SSH Failure exists: {ssh_result.failed}\nFailed SSH Hosts:")
        pprint.pprint(ssh_result.failed_hosts)
    if DATA_LOGGING==True:
        logger.info(f" - SSH Failure exists: {ssh_result.failed}")
        logger.info(" - Adding entries from ssh run to list")
    #create list to store host mac entries
    #TODO - only create lists in the collection process, don't pass on this list. Return and extend

    host_list = []
    ssh_host_list = add_entries(ssh_run,ssh_result,collect_function=collect_arp)
    if ssh_host_list!=None:
        host_list.extend(ssh_host_list)
    else:
        #TODO - Add logging and debuging for it. This returns to the main program.
        return None

    #remove duplicates because of dual core switches
    final_list = []
    #append first entry directly to avoid checking for key errors
    final_list.append(host_list[0])
    #Loop over host entries to check for multiple sitings of the same mac in arp tables
    for host_entry in host_list:
        #append the entry only if that mac address is not already in the list
        if host_entry["mac_address"] not in [final_item["mac_address"] for final_item in final_list]:
            final_list.append(host_entry)

    if DATA_LOGGING == True:
        logger.info(" - All entries have been gathered.")

    if SAVE_RESULTS == True:
        logger.info(" - Writing entries in file")
        arp_list = create_entries_rows(final_list,create_arp_row)
        save_the_list(arp_list, "arps.txt")
        logger.info(" - File closed.\nEND")
    if DEBUG_DATA == True:
        create_arp_table(final_list)

    return(final_list)

def initialize_inventory(nautobot_url,nautobot_token,filter_param_dict,nautobot_ssl_verify):
    #define inventory
    nr = InitNornir(
        inventory={
            "plugin": "NautobotInventory",
            "options": {
                "nautobot_url": nautobot_url,
                "nautobot_token": nautobot_token,
                "filter_parameters": filter_param_dict,
                "ssl_verify": nautobot_ssl_verify
            },
        },
    )
    return nr

def do_the_run(run,run_task,run_platform,run_workers,dev_username,dev_password,show_command):
    for item in run.inventory.hosts:
        run.inventory.hosts[item].platform = run_platform
        run.inventory.hosts[item].username = dev_username
        run.inventory.hosts[item].password = dev_password

    run.config.runner.options["num_workers"] = run_workers

    result = run.run(task=run_task,show_command=show_command)
    run.close_connections()
    return result

def do_the_run_multiple(run,run_task,run_platform,run_workers,dev_username,dev_password,show_commands):
    for item in run.inventory.hosts:
        run.inventory.hosts[item].platform = run_platform
        run.inventory.hosts[item].username = dev_username
        run.inventory.hosts[item].password = dev_password

    run.config.runner.options["num_workers"] = run_workers

    result_list = run.run(task=run_task,show_commands=show_commands)
    run.close_connections()
    return result_list

def enrich_node_mac_data(resolved_list:list,mac_list:list,SAVE_RESULTS=False,DEBUG_DATA=False, DATA_LOGGING=False):
    #TODO - Add global variables to handle the modes?
    node_list = []
    for each_mac in mac_list:
        for each_reshost in resolved_list:
            if each_mac['mac_address'] == each_reshost["mac_address"]:
                each_mac['host_ip'] = each_reshost["host_ip"]
                each_mac['host_name'] = each_reshost["host_name"]
                node_list.append(each_mac)
    
    if SAVE_RESULTS == True:
        if DATA_LOGGING == True:
            logger.info(" - Writing resolved entries in file")
        archive_node_list = create_entries_rows(node_list,create_host_row)
        save_the_list(archive_node_list, "hosts_data.txt")
        if DATA_LOGGING == True:
            logger.info(" - File closed.\nEND")

    return(node_list)

#TODO - Create single table creation function with params for title, fields, colors
def create_mac_table(host_list:list):
    localtime = time.asctime(time.localtime(time.time()))
    table = Table(title="MAC ADDRESS REPORT \n" + localtime)
    table.add_column("Mac Address", justify="center", style="green")
    table.add_column("Vlan", justify="center",style="yellow")
    table.add_column("Port", justify="center",style="red")
    table.add_column("Switch Name", justify="center",style="purple")
    table.add_column("IP Address", justify="center",style="blue")
    table.add_column("Location", justify="center",style="cyan")

    #TODO - slightly more complicated to add the correct fields to a list with a function
    for end_host in host_list:
        table.add_row(end_host['mac_address'],
                end_host['vlan'],
                end_host['port'],
                end_host['switch_name'],
                end_host['switch_address'],
                end_host['switch_location'])

    console = Console()
    console.print(table)
    return(table)

#TODO - Create single table creation function with params for title, fields, colors
def create_arp_table(host_list:list):
    localtime = time.asctime(time.localtime(time.time()))
    table = Table(title="ARP REPORT \n" + localtime)
    table.add_column("Mac Address", justify="center", style="green")
    table.add_column("IP Address", justify="center",style="blue")
    table.add_column("Interface", justify="center",style="yellow")
    table.add_column("Switch Name", justify="center",style="purple")
    table.add_column("Switch IP Address", justify="center",style="blue")
    table.add_column("Location", justify="center",style="cyan")

    #TODO - slightly more complicated to add the correct fields to a list with a function
    for end_host in host_list:
        table.add_row(end_host['mac_address'],
                end_host['host_ip'],
                end_host['vlan'],
                end_host['switch_name'],
                end_host['switch_address'],
                end_host['switch_location'])

    console = Console()
    console.print(table)
    return(table)

def create_entries_rows(host_list:list,row_function):
    row_list = []
    for end_host in host_list:
        row_list.append(row_function(end_host))
    return(row_list)

#TODO - Create mac description, fields and colors
def create_mac_fields():
    pass

#TODO - Create arp description, fields and colors
def create_arp_fileds():
    pass

#TODO - Create single row creation function with descriptions and fields
def create_row():
    pass

def create_mac_row(end_host):
    return(f"mac-address: {end_host['mac_address']}," 
                f"vlan: {end_host['vlan']},"
                f"port: {end_host['port']}," 
                f"switch: {end_host['switch_name']},switch-ip-address: {end_host['switch_address']},"
                f"switch-location: {end_host['switch_location']}\n")

def create_arp_row(end_host):
    return(f"mac-address: {end_host['mac_address']}," 
                f"ip-address: {end_host['host_ip']},"
                f"interface: {end_host['vlan']}," 
                f"switch: {end_host['switch_name']},switch-ip-address: {end_host['switch_address']},"
                f"switch-location: {end_host['switch_location']}\n")

def create_host_row(end_host):
    return(f"mac-address: {end_host['mac_address']},"
                f"host_ip: {end_host['host_ip']},host_name: {end_host['host_name']},"
                f"vlan: {end_host['vlan']},"
                f"port: {end_host['port']}," 
                f"switch: {end_host['switch_name']},switch-ip-address: {end_host['switch_address']},"
                f"switch-location: {end_host['switch_location']}\n")

def print_table(table):
    console = Console()
    console.print(table)
    return

def main():
    pass

if __name__ == "__main__":
    main()
