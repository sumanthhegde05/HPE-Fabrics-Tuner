"""#!/usr/bin/python2.7"""

# -*- coding: utf-8 -*-

import os
import subprocess
import time
import sys
import paramiko
from optparse import OptionParser,OptionGroup
from textwrap import dedent
import logging


GET_OS_NAME                     = "cat /etc/os-release | grep 'PRETTY_NAME'"
GET_KERNAL_VERSION              = "uname -r"
GET_BIOS_RELEASE_DATE           = "dmidecode -t bios | grep 'Release Date:'"
GET_BIOS_VERSION                = "dmidecode -t bios | grep 'Version:' | awk '{print $2}'"
GET_PROCESSOR_NAME              = "dmidecode -t processor | grep 'Version'"
GET_SOCKETS_COUNT               = "dmidecode -t processor | grep 'Version'"
GET_CORE_COUNT                  = "dmidecode -t processor | grep 'Core Count'"
GET_THREAD_COUNT                = "dmidecode -t processor | grep 'Thread Count'"
GET_MAX_SPEED                   = "dmidecode -t processor | grep 'Max Speed'"
GET_NUMA_NODE_COUNT             = "lscpu | grep NUMA"
GET_NO_OF_DIMMS                 = "dmidecode -t memory | grep 'Number Of Devices:'"
GET_DIMM_SIZE                   = "dmidecode -t memory | grep '^\s*Size:'"
GET_TOTAL_MEMORY                = "free | grep Mem | awk '{print $2}'"
GET_MEMORY_SPEED                = "dmidecode -t memory | grep '^\s*Speed:'"
GET_MEMORY_TYPE                 = "dmidecode -t memory | grep '^\s*Type:'"
GET_MLNX_DEVICES                = "lspci | grep -i mell"
GET_NUMA_NODE                   = "lspci -vvvs {0} | grep 'NUMA node:' | awk '{1}'"
GET_PART_NUMBER                 = "lspci -vvvs {0} | grep -i 'Part number:' | awk '{1}'"
GET_PRODUCT_NAME                = "lspci -vvvs {0} | grep -i 'Product name:'"
GET_PCI_SLOT                    = "lspci -vvvs {0} | grep -i 'Physical slot:' | awk '{1}'"
GET_LINK_SPEED                  = "lspci -vvvs {0} | grep -i 'LnkSta:' | awk '{1}'"
GET_LINK_WIDTH                  = "lspci -vvvs {0} | grep -i 'LnkSta:' | awk '{1}'"
GET_INTERFACE_NAME              = "ls -l /sys/class/infiniband/* | grep {0}"
GET_NW_INTERFCAE_NAME           = "ls -l /sys/class/net/* | grep '{0}'"
GET_CHIPSET                     = "lspci -vvvs {0}"
GET_FW_VERSION                  = "ethtool -i {0} | grep 'firmware-version:' | awk '{1}'"
GET_PSID                        = "ethtool -i {0} | grep 'Link detected' | awk '{1}'"
GET_CARD_TYPE                   = "lspci | grep -i mell | grep {0}"
GET_CARD_STATUS                 = "ethtool {0} | grep 'firmware-version:' | awk '{1}'"
GET_FIREWALL_STATUS             = "systemctl status firewalld | grep -i Active"
GET_IRQBALANCE_STATUS           = "systemctl status irqbalance | grep -i Active"
GET_LRO_ON                      = "ethtool -k {0} | grep -i large"
GET_RX_GRO_HW                   = "ethtool -k {0} | grep -i gro"
GET_TX_USECS                    = "ethtool -c {0} | grep -i 'tx-usecs:'"
GET_RX_USECS                    = "ethtool -c {0} | grep -i 'rx-usecs:'"
GET_IPV4_TCP_TIMESTAMPS         = "sysctl -x net.ipv4.tcp_timestamps | awk '{print $3}'"
GET_IPV4_TCP_SACK               = "sysctl -x net.ipv4.tcp_sack  | awk '{print $3}'"
GET_CORE_NETDV_MAX_BACKLOG      = "sysctl -x net.core.netdev_max_backlog | awk '{print $3}'"
GET_NET_CORE_RMEM_MAX           = "sysctl -x net.core.rmem_max | awk '{print $3}'"
GET_NET_CORE_WMEM_MAX           = "sysctl -x net.core.wmem_max | awk '{print $3}'"
GET_NET_CORE_RMEM_DEFAULT       = "sysctl -x net.core.rmem_default | awk '{print $3}'"
GET_NET_CORE_WMEM_DEFAULT       = "sysctl -x net.core.wmem_default | awk '{print $3}'"
GET_NET_CORE_OPTMEM_MAX         = "sysctl -x net.core.optmem_max | awk '{{print $3}}'"
GET_NET_IPV4_TCP_RMEM           = "sysctl -x net.ipv4.tcp_rmem"
GET_NET_IPV4_TCP_WMEM           = "sysctl -x net.ipv4.tcp_wmem"
GET_NET_IPV4_TCP_LOW_LATENCY    = "sysctl -x net.ipv4.tcp_low_latency | awk '{print $3}'"
GET_RING_PARAMETERS_TX          = "ethtool -g {0} | grep TX: | awk '{1}'"
GET_RING_PARAMETERS_RX          = "ethtool -g {0} | grep RX: | awk '{1}'"
GET_COMBINED_QUEUE              = "ethtool -l {0} | grep Combined: | awk '{1}'" 

SET_FIREWALL_OFF                    =   "systemctl stop firewalld"
SET_IRQBALANCE_OFF                  =   "systemctl stop irqbalance"
SET_LRO_ON                          =   "ethtool -K {} lro on"
SET_ADAPTIVE_TX_TXUSECS_TXFRAMES    =   "ethtool -C {0} adaptive-tx off tx-usecs {1} tx-frames 0"
SET_ADAPTIVE_RX_RXUSECS_RXFRAMES    =   "ethtool -C {0} adaptive-rx off rx-usecs {1} rx-frames 0"
SET_AFFINITY                        =   "/usr/sbin/set_irq_affinity_bynode.sh {0} {1}"
SET_IPV4_TCP_TIMESTAMPS             =   "sysctl -w net.ipv4.tcp_timestamps=0"
SET_IPV4_TCP_SACK                   =   "sysctl -w net.ipv4.tcp_sack=1"
SET_CORE_NETDV_MAX_BACKLOG          =   "sysctl -w net.core.netdev_max_backlog={}"
SET_NET_CORE_RMEM_MAX               =   "sysctl -w net.core.rmem_max={}"
SET_NET_CORE_WMEM_MAX               =   "sysctl -w net.core.wmem_max={}"
SET_NET_CORE_RMEM_DEFAULT           =   "sysctl -w net.core.rmem_default={}"
SET_NET_CORE_WMEM_DEFAULT           =   "sysctl -w net.core.wmem_default={} "
SET_NET_CORE_OPTMEM_MAX             =   "sysctl -w net.core.optmem_max={}"
SET_NET_IPV4_TCP_RMEM               =   "sysctl -w net.ipv4.tcp_rmem='{}'"
SET_NET_IPV4_TCP_WMEM               =   "sysctl -w net.ipv4.tcp_wmem='{}'"
SET_RING_PARAMETERS_TX_RX           =   "ethtool -G {} tx {} rx {}"
SET_COMBINED_QUEUE                  =   "ethtool -L {} combined {}"


"sysctl -w net.ipv4.tcp_low_latency=1 "

General_Power_Efficient_Compute =       "General_Power_Efficient_Compute"
General_Peak_Frequency_Compute =        "General_Peak_Frequency_Compute"
General_Throughput_Compute =            "General_Throughput_Compute"
Virtualization_Power_Efficient=         "Virtualization_ower_Efficient"
Virtualization_Max_Performance =        "Virtualization_Max_Performance"
Low_Latency =                           "Low_Latency"
Transactional_Application_Processing =  "Transactional_Application_Processing"
High_Performance_Compute=               "High_Performance_Compute (HPC)"
Decision_support =                      "Decision_Support"
Graphic_processing =                    "Graphic_Processing"
IO_throughput =                         "I/O_Throughput"
Custom =                                "Custom"

ALLOWED_PROFILES =  [
                        General_Power_Efficient_Compute,
                        General_Peak_Frequency_Compute,
                        General_Throughput_Compute,
                        Virtualization_Power_Efficient,
                        Virtualization_Max_Performance,
                        Low_Latency,
                        Transactional_Application_Processing,
                        High_Performance_Compute,
                        Decision_support,
                        Graphic_processing,
                        IO_throughput,
                        Custom
                    ]


help_message = "\n -v, --version                    :   print tool version and exit [default False]\
                \n -d, --debug                      :   Capture all the report info and save it as a tar ball \
                \n -r, --report                     :   Report HW/BIOS/OS status\
                \n -b, --hpe_bios                   :   Set HPE recommended BIOS settings \
                \n -a, --arch_bios                  :   Set processor vendor specific AMD/Intel/ARM recommended BIOS settings \
                \n -s, --os  Set                    :   HPE recommended OS settings \
                \n -i IP, --ilo=IP                  :   iLO IP to do remote BIOS update \
                \n -p PASSWORD, --password=PASSWORD :   iLO password while remote BIOS update \
                \n -u USERNAME, --username=USERNAME :   iLO username while remote BIOS update\
                \n -f PROFILE, --profile=PROFILE   :   Set choose from below list BIOS profile \
                \n                                      ['HIGH_THROUGHPUT',\
                \n                                       'IP_FORWARDING_MULTI_STREAM_THROUGHPUT',\
                \n                                       'IP_FORWARDING_MULTI_STREAM_PACKET_RATE', \
                \n                                       'IP_FORWARDING_MULTI_STREAM_0_LOSS', \
                \n                                       'IP_FORWARDING_SINGLE_STREAM', \
                \n                                       'IP_FORWARDING_SINGLE_STREAM_0_LOSS', \
                \n                                       'IP_FORWARDING_SINGLE_STREAM_SINGLE_PORT', \
                \n                                       'LOW_LATENCY_VMA','MULTICAST']\n \
                \n Examples: \
                \n The following are the standard usage of the tool. \
	            \n - 'hpefabrictuner'                      #Set both HPE recommended BIOS and OS tunings.\
 	            \n - 'hpefabrictuner --arch_bios'          #Set only AMD/Intel/ARM recommended BIOS settings.\
	            \n - 'hpefabrictuner –-hpe_bios'           #Set only HPE recommended BIOS settings.\
	            \n - 'hpefabrictuner –-os'                 #Set only HPE recommended OS tuning.\
	            \n - 'hpefabrictuner –-report'             #Report detailed report on Hardware/BIOS/OS \
	            \n - 'hpefabrictuner –-debug'              #Capture all the report info and save it as a tar ball\n"

class adapter_details:
    def __init__(self):
        self.name = 'None'
        self.flag = False
        self.Physical_slot = 'None'
        self.Chipset = 'None'
        self.Part_number = 'None'
        self.Product_name = 'None'
        self.Link_speed = 'None'
        self.Link_width = 'None'
        self.Interface_name = 'None'
        self.Network_if_name = 'None'
        self.NUMA_node = 'None'
        self.PSID = 'None'
        self.Card_type = 'None'
        self.Port_status = 'None'
        self.FW_version = 'None'
        
class adapter_os_details():
    def __init__(self):
        self.name = 'None'
        self.LRO_ON = 'None'
        self.Rx_gro_hw = 'None'
        self.Rx_usecs = 'None'
        self.Tx_usecs = 'None'
        self.Combined_queue = 'None'
        self.Ring_buffer_size_tx = 'None'
        self.Ring_buffer_size_rx = 'None'



        

def os_command(command):
    hostname = "192.168.2.131"
    password = "Hptc_ib"
    port = 22
    username = "root"
    sshClient = paramiko.SSHClient()
    sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshClient.connect(hostname, port, username, password)
    stdin, stdout, stderr = sshClient.exec_command(command)
    result = ''.join(stdout.readlines())
    return result
    """process = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE).communicate()
    result = process[0].decode()
    return result"""


def conversion(Total_memory , Dimm_size):
    Total_memory = int(Total_memory)
    inc=0
    memory_unit_dictionary = {1:'MB',
                              2:'GB',
                              3:'TB',
                              4:'PB'}
    
    while Total_memory>999:
        Total_memory//=1000
        inc+=1
        
    Total_memory = str(Total_memory)+memory_unit_dictionary[inc]
    temp = Dimm_size.split()[1].strip()
    Dimm_size = int(Dimm_size.split()[0])
    inc = 0
    
    while Dimm_size>999:
        Dimm_size//=1000
        inc+=1
        
    if temp in memory_unit_dictionary.values():
        for item in memory_unit_dictionary.keys():
            if temp == memory_unit_dictionary[item]:
                add_on = memory_unit_dictionary[item+inc]
                break
            
    Dimm_size = str(Dimm_size)+" "+add_on
    return Total_memory , Dimm_size


def get_Bus_id_list():
    
    mellanox_devices = os_command(GET_MLNX_DEVICES)
    mellanox_devices_list = mellanox_devices.strip().split('\n')
    temp_list = [ item.split()[0] for item in mellanox_devices_list]
    
    for elem in range(1,len(temp_list)):
        if temp_list[elem][:2]!=temp_list[elem-1][:2]:
            temp = adapter_details()
            temp.name = temp_list[elem]
            Bus_id_list.append(temp)
            


def get_mlnx_device_details():

    for bus_id in Bus_id_list:
        bus_id.Physical_slot = os_command(GET_PCI_SLOT.format(bus_id.name,'{print $3}')).strip()
        
        if bus_id.Physical_slot == '':
            bus_id.Physical_slot = 'LOM'
        bus_id.Part_number = os_command(GET_PART_NUMBER.format(bus_id.name,'{print $4}')).strip()
        bus_id.Product_name = os_command(GET_PRODUCT_NAME.format(bus_id.name)).strip().split(':')[-1]
        bus_id.Link_speed = os_command(GET_LINK_WIDTH.format(bus_id.name,'{print $3}')).strip().strip(',')
        bus_id.Link_width = os_command(GET_LINK_WIDTH.format(bus_id.name,'{print $5}')).strip().strip(',')
        bus_id.NUMA_node = os_command(GET_NUMA_NODE.format(bus_id.name,'{print $3}')).strip()
        bus_id.Chipset = os_command(GET_CHIPSET.format(bus_id.name)).split('\n')[0].split()[-1]
        
        if 'Connect' not in bus_id.Chipset:
            temp = os_command(GET_CHIPSET.format(bus_id.name)).split('\n')[0].split()
            bus_id.Chipset = temp[-2]+" "+temp[-1]
        bus_id.Interface_name = os_command(GET_INTERFACE_NAME.format(bus_id.name)).strip().split('/')[-1]
        
        
        if bus_id.Interface_name=='':
            bus_id.Interface_name = 'Check_Driver'
        bus_id.Network_if_name = os_command(GET_NW_INTERFCAE_NAME.format(bus_id.name)).strip().split('/')[-1]
        
        if bus_id.Network_if_name =='':
            bus_id.Network_if_name = 'Check_Driver'
            bus_id.FW_version = 'Check_Driver'
            bus_id.PSID = 'Check_Driver'
            bus_id.Port_status = 'Check_Driver'
            bus_id.flag = True
        else:
            bus_id.FW_version = os_command(GET_FW_VERSION.format(bus_id.Network_if_name,'{print $2}')).strip()
            bus_id.PSID = os_command(GET_PSID.format(bus_id.Network_if_name,'{print $3}')).lstrip('(').rstrip(')')
            bus_id.Port_status = os_command(GET_CARD_STATUS.format(bus_id.Network_if_name,'{print $3}')).strip()
            if bus_id.Port_status == 'yes':
                bus_id.Port_status = 'Up'
            else:
                bus_id.Port_status = 'Down' 
        bus_id.Card_type = ' '.join(os_command(GET_CARD_TYPE.format(bus_id.name)).split()[1:3]).strip(':')
        
def log():
    #logger.info("hey")
    """lscpu_data = os_command("lscpu")
    cpu_info = os_command("cat /proc/cpuinfo")
    logger.info(cpu_info)
    file = open('log.txt','w')
    file.close()
    with open("log.txt","a") as file:
        file.write('command = "lspcu"\n')
        file.write(lscpu_data+"\n\n")
        file.write('command = "cat /proc/cpuinfo"\n')
        file.write(cpu_info+"\n\n")
        file.write('command = "lspci | grep -i mell"\n')
        file.write(mellanox_devices+"\n\n")
    logger.info("Collected detailed system info to <>.txt")"""


class report:


    def get_os_details(self):
        self.Os_name = os_command(GET_OS_NAME).strip().split('=')[-1]
        self.Os_kernel_version = os_command(GET_KERNAL_VERSION).strip()


    def log_os_details(self):
        logger.info("\nOS : {} Kernel version is {} \n".format(self.Os_name,self.Os_kernel_version))


    def get_bios_details(self):
        self.Bios_release_date = os_command(GET_BIOS_RELEASE_DATE).strip()
        self.Bios_version =  os_command(GET_BIOS_VERSION).strip()
        

    def log_bios_details(self):
        logger.info("Bios : {} {} \n".format(self.Bios_version,self.Bios_release_date))

        
    def get_processor_details(self):
        self.processor_name = os_command(GET_PROCESSOR_NAME).split('\n')[0].split(':')[-1]
        self.Socket_count = len(os_command(GET_SOCKETS_COUNT).strip().split('\n'))
        self.Core_count = os_command(GET_CORE_COUNT).split('\n')[0].split(':')[-1].strip()
        self.Thread_count = os_command(GET_THREAD_COUNT).split('\n')[0].split(':')[-1].strip()
        self.Max_speed = os_command(GET_MAX_SPEED).split('\n')[0].split(':')[-1].strip()
        self.NUMA_node =  os_command(GET_NUMA_NODE_COUNT).strip().split('\n')[0].split(':')[-1].strip()
        


    def log_processor_details(self):
        logger.info("Processor : {}, Socket#{}, Core#{} ,Thread#{}, MaxSpeed#{}, NUMA_NODE(S)#{} \n".format(self.processor_name,self.Socket_count,self.Core_count,self.Thread_count,self.Max_speed,self.NUMA_node))


    def get_memory_details(self):
        count=0
        
        for item in os_command(GET_NO_OF_DIMMS).strip().split('\n'):
            count += int(item.strip().split(':')[-1])
        self.No_of_dimms = count
        
        count = 0
        
        for item in os_command(GET_DIMM_SIZE).strip().split('\n'):
            if 'No Module Installed' not in item:
                self.Dimm_size = item.strip().split(':')[-1].strip()
                count +=1
                
        self.Total_memory = os_command(GET_TOTAL_MEMORY).strip()
        self.Total_memory, self.Dimm_size = conversion(self.Total_memory,self.Dimm_size)
        self.No_of_active_dimms = count
        
        for item in os_command(GET_MEMORY_SPEED).strip().split('\n'):
            if 'Unknown' not in item:
                self.Dimm_speed = item.strip().split(':')[-1]
                break
            
        for item in os_command(GET_MEMORY_TYPE).strip().split('\n'):
            if 'Type Detail' not in item and 'Other' not in item:
                self.Dimm_type = item.strip().split(':')[-1]
                break


    def log_memory_details(self):    
        logger.info("Memory : Total Memory#{}, PerDIMM#{} {} {}, Populated DIMM's#{}\n".format(self.Total_memory,self.Dimm_size,self.Dimm_type,self.Dimm_speed,self.No_of_active_dimms))

    
    def log_mlnx_device_details(self):
        logger.info("Mellanox Devices :")
        for bus_id in Bus_id_list:
            logger.info("{} {} FW#{} PCISlot#{} NUMAnode#{} Lw#{} Ls#{} P/N#{} PSID#{} {} {} Type#{} Status#{}".format(bus_id.name,bus_id.Chipset,bus_id.FW_version,bus_id.Physical_slot,bus_id.NUMA_node,bus_id.Link_width,bus_id.Link_speed,bus_id.Part_number,bus_id.PSID,bus_id.Interface_name,bus_id.Network_if_name,bus_id.Card_type,bus_id.Port_status))
        for bus_id in Bus_id_list:
            if bus_id.flag:
                logger.warning("\033[93mWarning\033[0m : Check_driver = Driver is not installed or not loaded")
                break

class os_settings:

    def __init__(self):
        self.Recommended_Firewall_status = 'inactive (dead)'
        self.Recommended_IRQ_balance = 'inactive (dead)'
        self.Recommended_Ipv4_tcp_timestamps = 'Disable (0)'
        self.Recommended_Ipv4_tcp_sack = 'Enable (1)'
        self.Recommended_Netdv_max_backlog = '250000'
        self.Recommended_Core_rmem_max = '4194304'
        self.Recommended_Core_wmem_max = '4194304'
        self.Recommended_Core_rmem_default = '4194304'
        self.Recommended_Core_wmem_drefault = '4194304'
        self.Recommended_Core_optmem_max = '4194304'
        self.Recommended_Net_ipv4_tcp_rmem = '16777216'
        self.Recommended_Net_ipv4_tcp_wmem = '16777216'
        self.Recommended_Net_ipv4_tcp_low_latency = '1'
        self.Recommended_LRO_ON = 'on'
        self.Recommended_Rx_gro_hw = 'on'
        self.Recommended_Rx_usecs = '0'
        self.Recommended_Tx_usecs = '0'
        self.Recommended_Ring_buffer_size_tx = '8192'
        self.Recommended_Ring_buffer_size_rx = '8192'
        self.Recommended_Combined_queue = '16'
        
    def get_os_settings(self,name):
        global Old_adapter_os_setting_list
        global New_adapter_os_setting_list
        self.Firewall_status = ' '.join(os_command(GET_FIREWALL_STATUS).strip().split()[1:3]).lstrip()
        self.IRQ_balance = ' '.join(os_command(GET_IRQBALANCE_STATUS).strip().split()[1:3]).lstrip()
        self.Ipv4_tcp_timestamps = os_command(GET_IPV4_TCP_TIMESTAMPS).strip()
        if self.Ipv4_tcp_timestamps == '0':
            self.Ipv4_tcp_timestamps = 'Disable (0)'
        else:
            self.Ipv4_tcp_timestamps = 'Enable (1)'  
        self.Ipv4_tcp_sack = os_command(GET_IPV4_TCP_SACK).strip()
        if self.Ipv4_tcp_sack == '0':
            self.Ipv4_tcp_sack = 'Disable (0)'
        else:
            self.Ipv4_tcp_sack = 'Enable (1)'
        self.Netdv_max_backlog = os_command(GET_CORE_NETDV_MAX_BACKLOG).strip()
        self.Core_rmem_max = os_command(GET_NET_CORE_RMEM_MAX).strip()
        self.Core_wmem_max = os_command(GET_NET_CORE_WMEM_MAX).strip()
        self.Core_rmem_default = os_command(GET_NET_CORE_RMEM_DEFAULT).strip()
        self.Core_wmem_drefault = os_command(GET_NET_CORE_WMEM_DEFAULT).strip()
        self.Core_optmem_max = os_command(GET_NET_CORE_OPTMEM_MAX).strip()
        self.Net_ipv4_tcp_rmem = os_command(GET_NET_IPV4_TCP_RMEM).strip().split()[-1].lstrip()
        self.Net_ipv4_tcp_wmem = os_command(GET_NET_IPV4_TCP_WMEM).strip().split()[-1].lstrip()
        self.Net_ipv4_tcp_low_latency = os_command(GET_NET_IPV4_TCP_LOW_LATENCY).strip()
        
                
        
        for bus_id in Bus_id_list:
            temp = adapter_os_details()
            if bus_id.Network_if_name != "":
                temp.name = bus_id.name
                temp.LRO_ON = os_command(GET_LRO_ON.format(bus_id.Network_if_name)).strip().split(':')[-1].lstrip()
                temp.Rx_gro_hw = os_command(GET_RX_GRO_HW.format(bus_id.Network_if_name)).strip().split(':')[-1].lstrip()
                temp.Rx_usecs = os_command(GET_RX_USECS.format(bus_id.Network_if_name)).strip().split(':')[-1].lstrip()
                temp.Tx_usecs = os_command(GET_TX_USECS.format(bus_id.Network_if_name)).strip().split(':')[-1].lstrip()
                temp.Ring_buffer_size_tx = os_command(GET_RING_PARAMETERS_TX.format(bus_id.Network_if_name,'{print $2}')).split()
                temp.Ring_buffer_size_rx = os_command(GET_RING_PARAMETERS_RX.format(bus_id.Network_if_name,'{print $2}')).split()
                temp.Combined_queue = os_command(GET_COMBINED_QUEUE.format(bus_id.Network_if_name,'{print $2}')).split()
            name.append(temp)
        print(Old_adapter_os_setting_list,New_adapter_os_setting_list)
    def set_recommended_os_settings(self):
        os_command(SET_FIREWALL_OFF)
        os_command(SET_IRQBALANCE_OFF)
        os_command(SET_IPV4_TCP_TIMESTAMPS)
        os_command(SET_IPV4_TCP_SACK)
        os_command(SET_ADAPTIVE_TX_TXUSECS_TXFRAMES)
        os_command(SET_CORE_NETDV_MAX_BACKLOG.format(self.Recommended_Netdv_max_backlog))
        os_command(SET_NET_CORE_RMEM_MAX.format(self.Recommended_Core_rmem_max))
        os_command(SET_NET_CORE_WMEM_MAX.format(self.Recommended_Core_wmem_max))
        os_command(SET_NET_CORE_RMEM_DEFAULT.format(self.Recommended_Core_rmem_default))
        os_command(SET_NET_CORE_WMEM_DEFAULT.format(self.Recommended_Core_wmem_drefault))
        os_command(SET_NET_CORE_OPTMEM_MAX.format(self.Recommended_Core_optmem_max))
        os_command(SET_NET_IPV4_TCP_RMEM.format(self.Recommended_Net_ipv4_tcp_rmem))
        os_command(SET_NET_IPV4_TCP_WMEM.format(self.Recommended_Net_ipv4_tcp_wmem))
        for bus_id in Bus_id_list:
            if bus_id.Network_if_name != 'Check_Driver': 
                print(bus_id.Network_if_name)
                os_command(SET_LRO_ON.format(bus_id.Network_if_name))                  
                os_command(SET_ADAPTIVE_TX_TXUSECS_TXFRAMES.format(bus_id.Network_if_name,self.Recommended_Tx_usecs)) 
                print(self.Recommended_Tx_usecs) 
                os_command(SET_ADAPTIVE_RX_RXUSECS_RXFRAMES.format(bus_id.Network_if_name,self.Recommended_Rx_usecs))
                print(self.Recommended_Rx_usecs)
                #os_command(SET_AFFINITY.format(bus_id.NUMA_node,bus_id.Network_if_name))
                os_command(SET_RING_PARAMETERS_TX_RX.format(bus_id.Network_if_name,self.Recommended_Ring_buffer_size_tx,self.Recommended_Ring_buffer_size_rx ))
                print(self.Recommended_Ring_buffer_size_rx, self.Recommended_Ring_buffer_size_tx)
                os_command(SET_COMBINED_QUEUE.format(bus_id.Network_if_name,self.Recommended_Combined_queue))
        
    def log_set_os_settings(self , new):
        global Old_adapter_os_setting_list
        global New_adapter_os_setting_list
        string = ''
        if self.Firewall_status == new.Firewall_status:
            string += "    Firewall Status         :    "+self.Firewall_status+"\n"
        else:
            string += "    Firewall Status         :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Firewall_status,self.Firewall_status,new.Firewall_status)+"\n"
        if self.IRQ_balance == new.IRQ_balance:
            string += "    IRQ Balance             :    "+self.IRQ_balance+"\n"
        else:
            string += "    IRQ Balance             :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.IRQ_balance,self.IRQ_balance,new.IRQ_balance)+"\n"
        if self.Ipv4_tcp_timestamps == new.Ipv4_tcp_timestamps:
            string += "    TCP Timestamp           :    "+self.Ipv4_tcp_timestamps+"\n"
        else:
            string += "    TCP Timestamp           :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Ipv4_tcp_timestamps,self.Ipv4_tcp_timestamps,new.Ipv4_tcp_timestamps)+"\n"
        if self.Ipv4_tcp_sack == new.Ipv4_tcp_sack:
            string += "    TCP Selective Acks      :    "+self.Ipv4_tcp_sack+"\n"
        else:
            string += "    TCP Selective Acks      :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Ipv4_tcp_sack,self.Ipv4_tcp_sack,new.Ipv4_tcp_sack)+"\n"
        if self.Netdv_max_backlog == new.Netdv_max_backlog:
            string += "    Proc Input Queue        :    "+self.Netdv_max_backlog+"\n"
        else:
            string += "    Proc Input Queue        :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Netdv_max_backlog,self.Netdv_max_backlog,new.Netdv_max_backlog)+"\n"
        string += "    TCP Buffer Size:\n"
        if self.Core_rmem_max == new.Core_rmem_max:
            string += "        RMEM Max            :    "+self.Core_rmem_max+"\n"
        else:
            string += "        RMEM Max            :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Core_rmem_max,self.Core_rmem_max,new.Core_rmem_max)+"\n"
        if self.Core_wmem_max == new.Core_wmem_max:
            string += "        WMEM Max            :    "+self.Core_wmem_max+"\n"
        else:
            string += "        WMEM Max            :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Core_wmem_max,self.Core_wmem_max,new.Core_wmem_max)+"\n"
        if self.Core_rmem_default == new.Core_rmem_default:
            string += "        RMEM Default        :    "+self.Core_rmem_default+"\n"
        else:
            string += "        RMEM Default        :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Core_rmem_default, self.Core_rmem_default,new.Core_rmem_default)+"\n"
        if self.Core_wmem_drefault == new.Core_wmem_drefault:
            string += "        WMEM Default        :    "+self.Core_wmem_drefault+"\n"
        else:
            string += "        WMEM Default        :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Core_wmem_drefault,self.Core_wmem_drefault,new.Core_wmem_drefault)+"\n"
        if self.Core_optmem_max == new.Core_optmem_max:
            string += "        OPTMEM Max          :    "+self.Core_optmem_max+"\n"
        else:   
            string += "        OPTMEM Max          :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Core_optmem_max,self.Core_optmem_max,new.Core_optmem_max)+"\n"
        string += "    TCP Memory Size:\n"
        if self.Net_ipv4_tcp_rmem == new.Net_ipv4_tcp_rmem:
            string += "        TCP RMEM            :    "+self.Net_ipv4_tcp_rmem+"\n"
        else:
            string += "        TCP RMEM            :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Net_ipv4_tcp_rmem,self.Net_ipv4_tcp_rmem,new.Net_ipv4_tcp_rmem)+"\n"
        if self.Net_ipv4_tcp_wmem == new.Net_ipv4_tcp_wmem:
            string += "        TCP WMEM            :    "+self.Net_ipv4_tcp_wmem+"\n"
        else:  
            string += "        TCP WMEM            :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Net_ipv4_tcp_wmem,self.Net_ipv4_tcp_wmem,new.Net_ipv4_tcp_wmem)+"\n"
        if self.Net_ipv4_tcp_low_latency == new.Net_ipv4_tcp_low_latency:
            string += "    TCP Low Latency         :    "+self.Net_ipv4_tcp_low_latency+"\n"
        else:
            string += "    TCP Low Latency         :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(new.Net_ipv4_tcp_low_latency,self.Net_ipv4_tcp_low_latency,new.Net_ipv4_tcp_low_latency)+"\n"
        for index in range(len(Bus_id_list)):
            if Bus_id_list[index].Network_if_name == 'Check_Driver': 
                string += "    "+Bus_id_list[index].name+"    :   Check_Driver\n"
            else:
                string += "    "+Old_adapter_os_setting_list[index].name+"\n"
                if Old_adapter_os_setting_list[index].LRO_ON == New_adapter_os_setting_list[index].LRO_ON:
                    string += "        LRO                 :    "+Old_adapter_os_setting_list[index].LRO_ON+"\n"
                else:
                    string += "        LRO                 :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(New_adapter_os_setting_list[index].LRO_ON, Old_adapter_os_setting_list[index].LRO_ON , New_adapter_os_setting_list[index].LRO_ON)+"\n"    

                if Old_adapter_os_setting_list[index].Rx_gro_hw == New_adapter_os_setting_list[index].Rx_gro_hw:
                    string += "        GRO                 :    "+Old_adapter_os_setting_list[index].Rx_gro_hw+"\n"
                else:
                    string += "        GRO                 :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(New_adapter_os_setting_list[index].Rx_gro_hw , Old_adapter_os_setting_list[index].Rx_gro_hw , New_adapter_os_setting_list[index].Rx_gro_hw)+"\n"
                if Old_adapter_os_setting_list[index].Rx_usecs == New_adapter_os_setting_list[index].Rx_usecs:
                    string += "        Adaptive Rx         :    "+Old_adapter_os_setting_list[index].Rx_usecs+"\n"
                else:
                    string += "        Adaptive Rx         :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format( New_adapter_os_setting_list[index].Rx_usecs, Old_adapter_os_setting_list[index].Rx_usecs, New_adapter_os_setting_list[index].Rx_usecs)+"\n"
                if Old_adapter_os_setting_list[index].Tx_usecs == New_adapter_os_setting_list[index].Tx_usecs:
                    string += "        Adaptive Tx         :    "+Old_adapter_os_setting_list[index].Tx_usecs+"\n"
                else:
                    string += "        Adaptive Tx         :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(New_adapter_os_setting_list[index].Tx_usecs , Old_adapter_os_setting_list[index].Tx_usecs, New_adapter_os_setting_list[index].Tx_usecs)+"\n"
                if Old_adapter_os_setting_list[index].Ring_buffer_size_rx[1] == New_adapter_os_setting_list[index].Ring_buffer_size_rx[1]:
                    string += "        Ring_buffer_RX      :    "+Old_adapter_os_setting_list[index].Ring_buffer_size_rx[1]+"\n"
                else:
                    string += "        Ring_buffer_RX      :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(New_adapter_os_setting_list[index].Ring_buffer_size_rx[1] , Old_adapter_os_setting_list[index].Ring_buffer_size_rx[1], New_adapter_os_setting_list[index].Ring_buffer_size_rx[1])+"\n"
                if Old_adapter_os_setting_list[index].Ring_buffer_size_tx[1] == New_adapter_os_setting_list[index].Ring_buffer_size_tx[1]:
                    string += "        Ring_buffer_TX      :    "+Old_adapter_os_setting_list[index].Ring_buffer_size_tx[1]+"\n"
                else:
                    string += "        Ring_buffer_TX      :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(New_adapter_os_setting_list[index].Ring_buffer_size_tx[1] , Old_adapter_os_setting_list[index].Ring_buffer_size_tx[1],New_adapter_os_setting_list[index].Ring_buffer_size_tx[1])+"\n"
                if Old_adapter_os_setting_list[index].Combined_queue[1] == New_adapter_os_setting_list[index].Combined_queue[1]:
                    string += "        Combined queue      :    "+Old_adapter_os_setting_list[index].Combined_queue[1]+"\n"
                else:
                    string += "        Combined queue      :    {}  [ Note : Set from Current '{}' to HPE recommended '{}' ]".format(New_adapter_os_setting_list[index].Combined_queue[1] , Old_adapter_os_setting_list[index].Combined_queue[1], New_adapter_os_setting_list[index].Combined_queue[1])+"\n"
                print(Old_adapter_os_setting_list[index].Combined_queue,New_adapter_os_setting_list[index].Combined_queue)
        return string
        
    def log_report_os_settings(self):
        string = ''
        if self.Firewall_status == self.Recommended_Firewall_status: 
            string += "    Firewall Status         :    "+self.Firewall_status+"\n"
        else:
            string += "    Firewall Status         :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Firewall_status,self.Recommended_Firewall_status)+"\n"
        if self.IRQ_balance == self.Recommended_IRQ_balance:
            string += "    IRQ Balance             :    "+self.IRQ_balance+"\n"
        else:
            string += "    IRQ Balance             :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.IRQ_balance,self.Recommended_IRQ_balance)+"\n"
        if self.Ipv4_tcp_timestamps == self.Recommended_Ipv4_tcp_timestamps:
            string += "    TCP Timestamp           :    "+self.Ipv4_tcp_timestamps+"\n"
        else:
            string += "    TCP Timestamp           :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Ipv4_tcp_timestamps,self.Recommended_Ipv4_tcp_timestamps)+"\n"
        if self.Ipv4_tcp_sack == self.Recommended_Ipv4_tcp_sack:
            string += "    TCP Selective Acks      :    "+self.Ipv4_tcp_sack+"\n"
        else:
            string += "    TCP Selective Acks      :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Ipv4_tcp_sack,self.Recommended_Ipv4_tcp_sack)+"\n"
        if self.Netdv_max_backlog == self.Recommended_Netdv_max_backlog:
            string += "    Proc Input Queue        :    "+self.Netdv_max_backlog+"\n"
        else:
            string += "    Proc Input Queue        :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Netdv_max_backlog,self.Recommended_Netdv_max_backlog)+"\n"
        string += "\033[94m    TCP Buffer Size:\033[0m\n"
        if self.Core_rmem_max == self.Recommended_Core_rmem_max:
            string += "        RMEM Max            :    "+self.Core_rmem_max+"\n"
        else:
            string += "        RMEM Max            :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Core_rmem_max,self.Recommended_Core_rmem_max)+"\n"
        
        if self.Core_wmem_max == self.Recommended_Core_wmem_max:
            string += "        WMEM Max            :    "+self.Core_wmem_max+"\n"
        else:
            string += "        WMEM Max            :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Core_wmem_max,self.Recommended_Core_wmem_max)+"\n"
        
        if self.Core_rmem_default == self.Recommended_Core_rmem_default:
            string += "        RMEM Default        :    "+self.Core_rmem_default+"\n"
        else: 
            string += "        RMEM Default        :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Core_rmem_default,self.Recommended_Core_rmem_default)+"\n"
        
        if self.Core_wmem_drefault == self.Recommended_Core_wmem_drefault:
            string += "        WMEM Default        :    "+self.Core_wmem_drefault+"\n"
        else:
            string += "        WMEM Default        :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Core_wmem_drefault,self.Recommended_Core_wmem_drefault)+"\n"
        
        if self.Core_optmem_max == self.Recommended_Core_optmem_max:
            string += "        OPTMEM Max          :    "+self.Core_optmem_max+"\n"
        else:
            string += "        OPTMEM Max          :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Core_optmem_max, self.Recommended_Core_optmem_max)+"\n"
            
        string += "\033[94m    TCP Memory Size:\033[0m\n"
        if self.Net_ipv4_tcp_rmem == self.Recommended_Net_ipv4_tcp_rmem:
            string += "        TCP RMEM            :    "+self.Net_ipv4_tcp_rmem+"\n"
        else:
            string += "        TCP RMEM            :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Net_ipv4_tcp_rmem,self.Recommended_Net_ipv4_tcp_rmem)+"\n"
        
        if self.Net_ipv4_tcp_wmem == self.Recommended_Net_ipv4_tcp_wmem:
            string += "        TCP WMEM            :    "+self.Net_ipv4_tcp_wmem+"\n"
        else:
            string += "        TCP WMEM            :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Net_ipv4_tcp_wmem,self.Recommended_Net_ipv4_tcp_wmem)+"\n"
          
        if self.Net_ipv4_tcp_low_latency == self.Recommended_Net_ipv4_tcp_low_latency:
            string += "    TCP Low Latency         :    "+self.Net_ipv4_tcp_low_latency+"\n"
        else:
            string += "    TCP Low Latency         :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(self.Net_ipv4_tcp_low_latency,self.Recommended_Net_ipv4_tcp_low_latency)+"\n"
        
        for index in range(len(Bus_id_list)):
            if Bus_id_list[index].Network_if_name == 'Check_Driver': 
                string += "    "+Bus_id_list[index].name+"    :   Check_Driver"+"\n"
            else:
                string += "    "+Adapter_os_setting_list[index].name+"\n"
                
                if Adapter_os_setting_list[index].LRO_ON == self.Recommended_LRO_ON:
                    string += "        LRO                 :    "+Adapter_os_setting_list[index].LRO_ON+"\n"
                else:
                    string += "        LRO                 :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(Adapter_os_setting_list[index].LRO_ON , self.Recommended_LRO_ON)+"\n"
                
                if Adapter_os_setting_list[index].Rx_gro_hw == self.Recommended_Rx_gro_hw:
                    string += "        GRO                 :    "+Adapter_os_setting_list[index].Rx_gro_hw+"\n"
                else:
                    string += "        GRO                 :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(Adapter_os_setting_list[index].Rx_gro_hw , self.Recommended_Rx_gro_hw)+"\n"
                if Adapter_os_setting_list[index].Rx_usecs == self.Recommended_Rx_usecs:
                    string += "        Adaptive Rx         :    "+Adapter_os_setting_list[index].Rx_usecs+"\n"
                else:
                    string += "        Adaptive Rx         :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(Adapter_os_setting_list[index].Rx_usecs, self.Recommended_Rx_usecs)+"\n"
                if Adapter_os_setting_list[index].Tx_usecs == self.Recommended_Tx_usecs:
                    string += "        Adaptive Tx         :    "+Adapter_os_setting_list[index].Tx_usecs+"\n"
                else:
                    string += "        Adaptive Tx         :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(Adapter_os_setting_list[index].Tx_usecs, self.Recommended_Tx_usecs)+"\n"
                if Adapter_os_setting_list[index].Ring_buffer_size_rx[1] == self.Recommended_Ring_buffer_size_rx:
                    string += "        Ring_buffer_RX      :    "+Adapter_os_setting_list[index].Ring_buffer_size_rx[1]+"\n"
                else:
                    string += "        Ring_buffer_RX      :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(Adapter_os_setting_list[index].Ring_buffer_size_rx[1], self.Recommended_Ring_buffer_size_rx)+"\n"
                if Adapter_os_setting_list[index].Ring_buffer_size_tx[1] == self.Recommended_Ring_buffer_size_tx:
                    string += "        Ring_buffer_TX      :    "+Adapter_os_setting_list[index].Ring_buffer_size_tx[1]+"\n"
                else:
                    string += "        Ring_buffer_TX      :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(Adapter_os_setting_list[index].Ring_buffer_size_tx[1],self.Recommended_Ring_buffer_size_tx)+"\n"
                if Adapter_os_setting_list[index].Combined_queue[1] == self.Recommended_Combined_queue:
                    string += "        Combined queue      :    "+Adapter_os_setting_list[index].Combined_queue[1]+"\n"
                else:
                    string += "        Combined queue      :    {}    [\033[93m  Recommended\033[0m : \033[92m {}\033[0m ]".format(Adapter_os_setting_list[index].Combined_queue[1], self.Recommended_Combined_queue)+"\n"
 
        return string
        

def add_options (parser):
    parser.add_option("-h","--help",  help=help_message , action="store_true",default = False)
    parser.add_option("-d","--debug", help = "Capture all the report info and save it as a tar ball", action="store_true", default = False)
    parser.add_option("-r","--report", help = "Report HW/BIOS/OS status", action="store_true", default = False)
    parser.add_option("-v","--version", help = "print tool version and exit [default False]", action="store_true", default = False)
    parser.add_option("-b","--hpe_bios", help = "Set HPE recommended BIOS settings", action="store_true", default = False)
    parser.add_option("-a","--arch_bios", help = "Set processor vendor specific AMD/Intel/ARM recommended BIOS settings", action="store_true", default = False)
    parser.add_option("-s","--os", help = "Set HPE recommended OS settings", action="store_true", default = False)
    parser.add_option("-i","--ilo", help = "iLO IP to do remote BIOS update", default = None)
    parser.add_option("-p","--password", help = "iLO password while remote BIOS update", default = None)
    parser.add_option("-u","--username", help = "iLO username while remote BIOS update", default = None)
    parser.add_option("-P","--profile",     help = "Set profile and run it. choose from: %s"%(ALLOWED_PROFILES),default = None)


def initialize():
    add_options(parser)
    (options, args) = parser.parse_args()
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler("error.log",mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(levelname)s : %(message)s'))
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return options , logger



if __name__=='__main__':
 
    Bus_id_list = []
    Old_adapter_os_setting_list = []
    New_adapter_os_setting_list = []
    Adapter_os_setting_list = []
    parser = OptionParser(add_help_option=False)
    options , logger = initialize()
  
    if options.help:
        logger.info(help_message)
       
        sys.exit()

    get_Bus_id_list()
    get_mlnx_device_details()   
    
    if options.report:
        report = report()
        report.get_os_details()
        report.log_os_details()
        report.get_bios_details()
        report.log_bios_details()
        report.get_processor_details()
        report.log_processor_details()
        report.get_memory_details()
        report.log_memory_details()
        report.log_mlnx_device_details()
        
        Os_settings = os_settings()
        Os_settings.get_os_settings(Adapter_os_setting_list)
        print(Os_settings.log_report_os_settings())
        

    elif options.os:
        Old_os_settings = os_settings()
        Old_os_settings.get_os_settings(Old_adapter_os_setting_list)
        Old_os_settings.set_recommended_os_settings()
        New_os_settings = os_settings()
        New_os_settings.get_os_settings(New_adapter_os_setting_list)
        print(Old_os_settings.log_set_os_settings(New_os_settings))
