#!/usr/bin/env python
import socket
import time
import os
from subprocess import Popen, DEVNULL

from ttp import ttp
from ip_arp_template import ttp_template as arp_ttp_template
from mactemplate import ttp_template as mac_ttp_template

from rich.console import Console
from rich.table import Table

import itertools


def load_iparp_list(filepath:str):
    with open(filepath) as ip_arp_file:
        file_content = ip_arp_file.read().rstrip("\n")

    parser = ttp(data=file_content, template=arp_ttp_template)
    parser.parse()
    # Results as multiline string
    node_address_list = parser.result()[0][0]["ip-arps"]

    return(node_address_list)

def load_macs(filepath:str):
    
    with open(filepath) as macs_file:
        file_content = macs_file.read().rstrip("\n")
            
    parser = ttp(data=file_content, template=mac_ttp_template)
    parser.parse()
    # Results as multiline string
    mac_address_list = parser.result()[0][0]["mac-addresses"]

    return(mac_address_list)

def ping(ip_list:list):
    #clear = "clear"
    #os.system(clear)
    localtime = time.asctime(time.localtime(time.time()))
    active_list = []
    inactive_list = []
    p = {}
    #with open('reader.txt', 'r') as f:
    #    filelines = f.readlines()
    for n in ip_list:
        ip = n["host_ip"]
        p[ip] = Popen(['ping', '-c', '4', '-i', '0.2', ip], stdout=DEVNULL)

    while p:
        for ip, proc in p.items():
            if proc.poll() is not None:
                del p[ip]
                if proc.returncode == 0:
                    active_list.append(ip)
                elif proc.returncode == 1:
                    inactive_list.append(ip)
                else:
                    print(f"{ip} ERROR")
                break

    print_2col_table("PING REPORT",active_list,"Active Hosts",inactive_list,"Inactive Hosts",localtime)

    return active_list,inactive_list

def print_2col_table(table_title:str,col_a:list, col_a_subject:str,col_b:list,col_b_subject:str,localtime:str):
    table = Table(title=table_title+" \n"+localtime)
    table.add_column(col_a_subject, justify="center", style="green")
    table.add_column(col_b_subject, justify="center",style="red")
    for (a,i) in itertools.zip_longest(col_a,col_b):
        table.add_row(a,i)
    console = Console()
    console.print(table)
    return()

def node_resolve(nodelist:list):
    
    not_resolved = []

    for node_data in nodelist:
        node = dict()
        node_address = node_data["host_ip"]
        #print(node_data["host_ip"])
        try:
            #TODO - I need to just add info to the nodelist, not create new lists. Either a hostname or blank or null.
            node_hostname = socket.gethostbyaddr(node_address)[0]
            #ip_address = socket.gethostbyname(printername)
            node_data["host_name"] = node_hostname
        except Exception:
            node_data["host_name"] = ""
            not_resolved.append(node_address)
            continue

    #print unresolved - this prints all data, like port, switch, etc.
    #print("These ip addresses are not resolved:")
    #for unknown_ip in not_resolved:
    #    print(unknown_ip)
    if len(nodelist)!=0:
        return(nodelist)
    else:
        return None

def save_the_list(entries_list:list, filepath:str):
    with open(filepath, 'w') as writer:
        for line in entries_list:
            writer.write(line)
    return()

#TODO - When the process of adding arp entries to arp list and adding to the table are separated, this function will print the table.
def print_the_list(arp_list:list):
    pass
    return()

def main():
    pass
    return()

if __name__ == "__main__":
    main()
