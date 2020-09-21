#!/usr/bin/python3.6

# -*- coding: utf-8 -*-

import os
import subprocess
import time
import sys
from optparse import OptionParser,OptionGroup
from textwrap import dedent
import logging
from datetime import datetime


GET_SERVER_MANUFACTURER_NAME        =   "dmidecode -t system | grep Manufacturer | awk '{print $2}'"
GET_SERVER_PRODUCT_NAME             =   "dmidecode -t system | grep 'Product Name'"
GET_OS_NAME                         =   "cat /etc/os-release | grep 'PRETTY_NAME'"
GET_KERNAL_VERSION                  =   "uname -r"
GET_BIOS_RELEASE_DATE               =   "dmidecode -t bios | grep 'Release Date:'"
GET_BIOS_VERSION                    =   "dmidecode -t bios | grep 'Version:' | awk '{print $2}'"
GET_PROCESSOR_NAME                  =   "dmidecode -t processor | grep 'Version'"
GET_SOCKETS_COUNT                   =   "dmidecode -t processor | grep 'Version'"
GET_CORE_COUNT                      =   "dmidecode -t processor | grep 'Core Count'"
GET_THREAD_COUNT                    =   "dmidecode -t processor | grep 'Thread Count'"
GET_MAX_SPEED                       =   "dmidecode -t processor | grep 'Max Speed'"
GET_NUMA_NODE_COUNT                 =   "lscpu | grep NUMA"
GET_NO_OF_DIMMS                     =   "dmidecode -t memory | grep 'Number Of Devices:'"
GET_DIMM_SIZE                       =   "dmidecode -t memory | grep '^\s*Size:'"
GET_TOTAL_MEMORY                    =   "free | grep Mem | awk '{print $2}'"
GET_MEMORY_SPEED                    =   "dmidecode -t memory | grep '^\s*Speed:'"
GET_MEMORY_TYPE                     =   "dmidecode -t memory | grep '^\s*Type:'"
GET_MLNX_DEVICES                    =   "lspci | grep -i mell"
GET_NUMA_NODE                       =   "lspci -vvvs {0} | grep 'NUMA node:' | awk '{1}'"
GET_PART_NUMBER                     =   "lspci -vvvs {0} | grep -i 'Part number:' | awk '{1}'"
GET_PRODUCT_NAME                    =   "lspci -vvvs {0} | grep -i 'Product name:'"
GET_PCI_SLOT                        =   "lspci -vvvs {0} | grep -i 'Physical slot:' | awk '{1}'"
GET_LINK_SPEED                      =   "lspci -vvvs {0} | grep -i 'LnkSta:' | awk '{1}'"
GET_LINK_WIDTH                      =   "lspci -vvvs {0} | grep -i 'LnkSta:' | awk '{1}'"
GET_INTERFACE_NAME                  =   "ls -l /sys/class/infiniband/* | grep {0}"
GET_NW_INTERFCAE_NAME               =   "ls -l /sys/class/net/* | grep '{0}'"
GET_CHIPSET                         =   "lspci -vvvs {0}"
GET_FW_VERSION                      =   "ethtool -i {0} | grep 'firmware-version:' | awk '{1}'"
GET_PSID                            =   "ethtool -i {0} | grep 'firmware-version:' | awk '{1}'"
GET_CARD_TYPE                       =   "lspci | grep -i mell | grep {0}"
GET_CARD_STATUS                     =   "ethtool {0} | grep 'Link detected' | awk '{1}'"
GET_FIREWALL_STATUS                 =   "systemctl status firewalld | grep -i Active"
GET_IRQBALANCE_STATUS               =   "systemctl status irqbalance | grep -i Active"
GET_LRO_ON                          =   "ethtool -k {0} | grep -i large"
GET_RX_GRO_HW                       =   "ethtool -k {0} | grep -i gro"
GET_TX_USECS                        =   "ethtool -c {0} | grep -i 'tx-usecs:'"
GET_RX_USECS                        =   "ethtool -c {0} | grep -i 'rx-usecs:'"
GET_IPV4_TCP_TIMESTAMPS             =   "sysctl -x net.ipv4.tcp_timestamps | awk '{print $3}'"
GET_IPV4_TCP_SACK                   =   "sysctl -x net.ipv4.tcp_sack  | awk '{print $3}'"
GET_CORE_NETDV_MAX_BACKLOG          =   "sysctl -x net.core.netdev_max_backlog | awk '{print $3}'"
GET_NET_CORE_RMEM_MAX               =   "sysctl -x net.core.rmem_max | awk '{print $3}'"
GET_NET_CORE_WMEM_MAX               =   "sysctl -x net.core.wmem_max | awk '{print $3}'"
GET_NET_CORE_RMEM_DEFAULT           =   "sysctl -x net.core.rmem_default | awk '{print $3}'"
GET_NET_CORE_WMEM_DEFAULT           =   "sysctl -x net.core.wmem_default | awk '{print $3}'"
GET_NET_CORE_OPTMEM_MAX             =   "sysctl -x net.core.optmem_max | awk '{{print $3}}'"
GET_NET_IPV4_TCP_RMEM               =   "sysctl -x net.ipv4.tcp_rmem"
GET_NET_IPV4_TCP_WMEM               =   "sysctl -x net.ipv4.tcp_wmem"
GET_NET_IPV4_TCP_LOW_LATENCY        =   "sysctl -x net.ipv4.tcp_low_latency | awk '{print $3}'"
GET_RING_PARAMETERS_TX              =   "ethtool -g {0} | grep TX: | awk '{1}'"
GET_RING_PARAMETERS_RX              =   "ethtool -g {0} | grep RX: | awk '{1}'"
GET_COMBINED_QUEUE                  =   "ethtool -l {0} | grep Combined: | awk '{1}'" 
GET_BIOS_SETTINGS                   =   "ilorest --nocache get --select Bios. | grep -E 'WorkloadProfile|ProcHyperthreading|ProcSMT|PreferredIOBusEnable|PreferredIOBusNumber|ProcAmdIOMMU|NumaMemoryDomainsPerSocket|LastLevelCacheAsNUMANode|TransparentSecureMemoryEncryption|DeterminismControl|PerformanceDeterminism|ProcX2Apic|DataFabricCStateEnable|InfinityFabricPstate|CStateEfficiencyMode|MinProcIdlePower|PowerRegulator|XGMIForceLinkWidth|XGMIMaxLinkWidth'"
GET_TYPE_OF_PROCESSOR               =   "dmidecode -t processor | grep 'Manufacturer:' | awk '{print $2}'"
GET_LSCPU_DETAILS                   =   "lscpu"
GET_CPUINFO                         =   "cat /proc/cpuinfo"
GET_MEMINFO                         =   "cat /proc/meminfo"
GET_IBSTAT                          =   "ibstat"
GET_IP_LINK                         =   "ip link"
GET_IP_CONFIG                       =   "ifconfig -a"
GET_MODINFO_MLX4_CORE               =   "modinfo mlx4_core | tr '<>' '[]'"
GET_MODINFO_MLX4_IB                 =   "modinfo mlx4_ib | tr '<>' '[]'"
GET_MODINFO_MLX4_EN                 =   "modinfo mlx4_en | tr '<>' '[]'"
GET_MODINFO_MLX5_CORE               =   "modinfo mlx5_core | tr '<>' '[]'"
GET_MODINFO_MLX5_IB                 =   "modinfo mlx5_ib | tr '<>' '[]'"
GET_IBV_DEVICES                     =   "ibv_devices"
GET_IBV_DEVINFO                     =   "ibv_devinfo"
GET_IB_NODES                        =   "ibnodes"
GET_IB_NETDISCOVER                  =   "ibnetdiscover"
GET_IB_NETDISCOVER_P                =   "ibnetdiscover -p"
GET_DMIDECODE                       =   "dmidecode"
GET_INTERFACE_DETAILS               =   "ls -l /sys/class/infiniband/*"
GET_NETWORK_IF_DETAILS              =   "ls -l /sys/class/net/*"

SET_FIREWALL_OFF                    =   "systemctl {} firewalld"
SET_IRQBALANCE_OFF                  =   "systemctl {} irqbalance"
SET_IPV4_TCP_TIMESTAMPS             =   "sysctl -w net.ipv4.tcp_timestamps={}"
SET_IPV4_TCP_SACK                   =   "sysctl -w net.ipv4.tcp_sack={}"
SET_LRO_ON                          =   "ethtool -K {} lro on"
SET_ADAPTIVE_TX_TXUSECS_TXFRAMES    =   "ethtool -C {0} adaptive-tx off tx-usecs {1} tx-frames 0"
SET_ADAPTIVE_RX_RXUSECS_RXFRAMES    =   "ethtool -C {0} adaptive-rx off rx-usecs {1} rx-frames 0"
SET_AFFINITY                        =   "/usr/sbin/set_irq_affinity_bynode.sh {0} {1}"
SET_CORE_NETDV_MAX_BACKLOG          =   "sysctl -w net.core.netdev_max_backlog={}"
SET_NET_CORE_RMEM_MAX               =   "sysctl -w net.core.rmem_max={}"
SET_NET_CORE_WMEM_MAX               =   "sysctl -w net.core.wmem_max={}"
SET_NET_CORE_RMEM_DEFAULT           =   "sysctl -w net.core.rmem_default={}"
SET_NET_CORE_WMEM_DEFAULT           =   "sysctl -w net.core.wmem_default={}"
SET_NET_CORE_OPTMEM_MAX             =   "sysctl -w net.core.optmem_max={}"
SET_NET_IPV4_TCP_RMEM               =   "sysctl -w net.ipv4.tcp_rmem='{}'"
SET_NET_IPV4_TCP_WMEM               =   "sysctl -w net.ipv4.tcp_wmem='{}'"
SET_RING_PARAMETERS_TX_RX           =   "ethtool -G {} tx {} rx {}"
SET_COMBINED_QUEUE                  =   "ethtool -L {} combined {}"
SET_IPV4_LOW_LATENCY                =   "sysctl -w net.ipv4.tcp_low_latency=1"


General_Power_Efficient_Compute         =   "General_Power_Efficient_Compute"
General_Peak_Frequency_Compute          =   "General_Peak_Frequency_Compute"
General_Throughput_Compute              =   "General_Throughput_Compute"
Virtualization_Power_Efficient          =   "Virtualization_ower_Efficient"
Virtualization_Max_Performance          =   "Virtualization_Max_Performance"
Low_Latency                             =   "Low_Latency"
Transactional_Application_Processing    =   "Transactional_Application_Processing"
High_Performance_Compute                =   "High_Performance_Compute (HPC)"
Decision_support                        =   "Decision_Support"
Graphic_processing                      =   "Graphic_Processing"
IO_throughput                           =   "I/O_Throughput"
Custom                                  =   "Custom"



COMMANDS_FOR_LOG_FILE = [   
                            GET_LSCPU_DETAILS, 
                            GET_MEMINFO,
                            GET_MLNX_DEVICES,
                            GET_CHIPSET, 
                            GET_IBSTAT, 
                            GET_IP_LINK,
                            GET_IP_CONFIG,                    
                            GET_MODINFO_MLX4_CORE,
                            GET_MODINFO_MLX4_IB, 
                            GET_MODINFO_MLX4_EN, 
                            GET_MODINFO_MLX5_CORE, 
                            GET_MODINFO_MLX5_IB, 
                            GET_IBV_DEVICES,
                            GET_IBV_DEVINFO, 
                            GET_IB_NODES, 
                            GET_IB_NETDISCOVER, 
                            GET_IB_NETDISCOVER_P,
                            GET_INTERFACE_DETAILS,
                            GET_NETWORK_IF_DETAILS,
                            GET_CPUINFO,
                            GET_DMIDECODE          
                        ]


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
                \n -f PROFILE, --profile=PROFILE    :   Set choose from below list BIOS profile \
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
	            \n - 'hpefabrictuner --hpe_bios'           #Set only HPE recommended BIOS settings.\
	            \n - 'hpefabrictuner --os'                 #Set only HPE recommended OS tuning.\
	            \n - 'hpefabrictuner --report'             #Report detailed report on Hardware/BIOS/OS \
	            \n - 'hpefabrictuner --debug'              #Capture all the report info and save it as a tar ball\n"


class colors:
    red         = '\033[31m'
    green       = '\033[32m'
    yellow      = '\033[33m'
    blue        = '\033[34m'
    violet      = '\033[35m'
    cyan        = '\033[36m'
    
    bred        = '\033[1;31m'
    bgreen      = '\033[1;32m'
    byellow     = '\033[1;33m'
    bblue       = '\033[1;34m'
    bviolet     = '\033[1;35m'
    bcyan       = '\033[1;36m'
    
    lred        = '\033[91m'
    lgreen      = '\033[92m'
    lyellow     = '\033[93m'
    lblue       = '\033[94m'
    lmagenta    = '\033[95m'
    lcyan       = '\033[96m'
    
    blred       = '\033[1;91m'
    blgreen     = '\033[1;92m'
    blyellow    = '\033[1;93m'
    blbblue     = '\033[1;94m'
    blmagenta   = '\033[1;95m'
    blcyan      = '\033[1;96m'
    
    END='\033[0m'


def get_date_and_time():
    """
    Method that returns the current date and time of the sysem in m/d/y_h/m/s format.
    """
    now = datetime.now()
    string = now.strftime("%m%d%y_%H%M%S")
    return string


def os_command(command):
    """
    Method used to run all os commands on the system.
    """
    process = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    result = process[0].decode()
    return result


def add_options (parser):
    """
    Method that defines the options(prameters) for the script.
    """
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
    file_handler = logging.FileHandler("debug.log",mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(levelname)s : %(message)s'))
    """console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(message)s'))"""
    logger.addHandler(file_handler)
    #logger.addHandler(console_handler)
    return options , logger

    
def write_info_to_file(file_path, info , display):
    """
    Method used to display the output and write it to the log file.
    """
    if display == True:
        print(info)
    log = open(file_path,'a')
    log.write(str(info))
    log.close()


def conversion(Total_memory , Dimm_size):
    """
    Method used to convert the memory into a readable format.
    """
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


class adapter_details:
    """
    class containing attributes of the adapter(used in displaying mlnx device details).
    """
    def __init__(self):
        self.flag = False
        self.name = 'Unknown'
        self.Physical_slot = 'Unknown'
        self.Chipset = 'Unknown'
        self.Part_number = 'Unknown'
        self.Product_name = 'Unknown'
        self.Link_speed = 'Unknown'
        self.Link_width = 'Unknown'
        self.Interface_name = 'Unknown'
        self.Network_if_name = 'Unknown'
        self.NUMA_node = 'Unknown'
        self.PSID = 'Unknown'
        self.Card_type = 'Unknown'
        self.Port_status = 'Unknown'
        self.FW_version = 'Unknown'
        
        
class adapter_os_details():
    """
    class containing attributes of the adapter(used in displaying os setting details)
    """
    def __init__(self):
        self.name = 'Unknown'
        self.LRO_ON = 'Unknown'
        self.Rx_gro_hw = 'Unknown'
        self.Rx_usecs = 'Unknown'
        self.Tx_usecs = 'Unknown'
        self.Combined_queue = 'Unknown'
        self.Ring_buffer_size_tx = 'Unknown'
        self.Ring_buffer_size_rx = 'Unknown'


def get_mlnx_device_details():
    """
    Method helps to get the mlnx device details.
    """
    global Bus_id_list
    mellanox_devices = os_command(GET_MLNX_DEVICES)
    mellanox_devices_list = mellanox_devices.strip().split('\n')
    temp_list = [ item.split()[0] for item in mellanox_devices_list]
    temp = adapter_details()
    temp.name = temp_list[0]
    Bus_id_list.append(temp)
    for elem in range(1,len(temp_list)):
        if temp_list[elem][:2]!=temp_list[elem-1][:2]:
            temp = adapter_details()
            temp.name = temp_list[elem]
            Bus_id_list.append(temp)
        
    for bus_id in Bus_id_list:
        #print(bus_id.name)
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
            bus_id.PSID = os_command(GET_PSID.format(bus_id.Network_if_name,'{print $3}')).replace('(','').replace(')','').strip()
            bus_id.Port_status = os_command(GET_CARD_STATUS.format(bus_id.Network_if_name,'{print $3}')).strip()
            if bus_id.Port_status == 'yes':
                bus_id.Port_status = 'Up'
            else:
                bus_id.Port_status = 'Down' 
        bus_id.Card_type = ' '.join(os_command(GET_CARD_TYPE.format(bus_id.name)).split()[1:3]).strip(':')
        
        
    string = colors.lblue+"Mellanox Devices"+colors.END+" : \n"
    
    for bus_id in Bus_id_list:
        string += colors.violet+bus_id.name+colors.END+" "+bus_id.Chipset+" "
        string += colors.violet+"FW"+colors.END+"#"+bus_id.FW_version+" "
        string += colors.violet+"PCISlot"+colors.END+"#"+bus_id.Physical_slot+" "
        string += colors.violet+"NUMAnode"+colors.END+"#"+bus_id.NUMA_node+" "
        string += colors.violet+"Lw"+colors.END+"#"+bus_id.Link_width+" "
        string += colors.violet+"Ls"+colors.END+"#"+bus_id.Link_speed+" " 
        string += colors.violet+"P/N"+colors.END+"#"+bus_id.Part_number+" "
        string += colors.violet+"PSID"+colors.END+"#"+bus_id.PSID+" "+bus_id.Interface_name+" "+bus_id.Network_if_name+" "
        string += colors.violet+"Type"+colors.END+"#"+bus_id.Card_type+" "
        string += colors.violet+"LnkStat"+colors.END+"#"+bus_id.Port_status+"\n"
    
    for bus_id in Bus_id_list:
        if bus_id.flag:
            string += colors.yellow+"Warning"+colors.END+" : Check_driver = Driver is not installed or not loaded\n"
            break
    return string
        

class server_details:
    """
    class containing all the server details.
    """
    def get_os_details(self):
        """
        Method to fetch os details.
        """
        self.Os_name = os_command(GET_OS_NAME).strip().split('=')[-1]
        self.Os_kernel_version = os_command(GET_KERNAL_VERSION).strip()

        string = colors.lblue+"OS : "+colors.END+self.Os_name
        string += "Kernel version is "+self.Os_kernel_version+"\n"
        return string


    def get_bios_details(self):
        """
        Method to fetch Bios details.
        """
        self.Bios_release_date = os_command(GET_BIOS_RELEASE_DATE).strip()
        self.Bios_version =  os_command(GET_BIOS_VERSION).strip()
        
        string = colors.lblue+"Bios"+colors.END+" : "+self.Bios_version+" "
        string += self.Bios_release_date+"\n"
        return string
        

    def get_processor_details(self):
        """
        Method to fetch processor details.
        """
        self.processor_name = os_command(GET_PROCESSOR_NAME).split('\n')[0].split(':')[-1]
        self.Socket_count = str(len(os_command(GET_SOCKETS_COUNT).strip().split('\n')))
        self.Core_count = os_command(GET_CORE_COUNT).split('\n')[0].split(':')[-1].strip()
        self.Thread_count = os_command(GET_THREAD_COUNT).split('\n')[0].split(':')[-1].strip()
        self.Max_speed = os_command(GET_MAX_SPEED).split('\n')[0].split(':')[-1].strip()
        self.NUMA_node =  os_command(GET_NUMA_NODE_COUNT).strip().split('\n')[0].split(':')[-1].strip()
        
        string = colors.lblue+"Processor"+colors.END+" : "+self.processor_name+", "
        string += colors.violet+"Socket"+colors.END+"#"+self.Socket_count+", "
        string += colors.violet+"Core"+colors.END+"#"+self.Core_count+", "
        string += colors.violet+"Thread"+colors.END+"#"+self.Thread_count+", "
        string += colors.violet+"MaxSpeed"+colors.END+"#"+self.Max_speed+", "
        string += colors.violet+"NUMA_NODE(S)"+colors.END+"#"+self.NUMA_node+" \n"
        return string  


    def get_memory_details(self):
        """
        Method to get memory details.
        """
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
        self.No_of_active_dimms = str(count)
        
        for item in os_command(GET_MEMORY_SPEED).strip().split('\n'):
            if 'Unknown' not in item:
                self.Dimm_speed = item.strip().split(':')[-1]
                break
            
        for item in os_command(GET_MEMORY_TYPE).strip().split('\n'):
            if 'Type Detail' not in item and 'Other' not in item:
                self.Dimm_type = item.strip().split(':')[-1]
                break

        string = colors.lblue+"Memory"+colors.END+" : "
        string += colors.violet+"Total Memory"+colors.END+"#"+self.Total_memory+", "
        string += colors.violet+"PerDIMM"+colors.END+"#"+self.Dimm_size+" "+self.Dimm_type+" "+self.Dimm_speed+", "
        string +=  colors.violet+"Populated DIMM's"+colors.END+"#"+self.No_of_active_dimms+"\n"
        return string


class os_settings:
    """
    Class containing details about os settings.
    """
    def __init__(self):
        """
        Initializing with HPE recommended os settings.
        """
        self.Recommended_Firewall_status            =   'inactive (dead)'
        self.Recommended_IRQ_balance                =   'inactive (dead)'
        self.Recommended_Ipv4_tcp_timestamps        =   'Disable (0)'
        self.Recommended_Ipv4_tcp_sack              =   'Enable (1)'
        self.Recommended_Netdv_max_backlog          =   '250000'
        self.Recommended_Core_rmem_max              =   '4194304'
        self.Recommended_Core_wmem_max              =   '4194304'
        self.Recommended_Core_rmem_default          =   '4194304'
        self.Recommended_Core_wmem_drefault         =   '4194304'
        self.Recommended_Core_optmem_max            =   '4194304'
        self.Recommended_Net_ipv4_tcp_rmem          =   '16777216'
        self.Recommended_Net_ipv4_tcp_wmem          =   '16777216'
        self.Recommended_Net_ipv4_tcp_low_latency   =   '1'
        self.Recommended_LRO_ON                     =   'on'
        self.Recommended_Rx_gro_hw                  =   'on'
        self.Recommended_Rx_usecs                   =   '0'
        self.Recommended_Tx_usecs                   =   '0'
        self.Recommended_Ring_buffer_size_tx        =   '8192'
        self.Recommended_Ring_buffer_size_rx        =   '8192'
        self.Recommended_Combined_queue             =   '16'
        

    def get_os_settings(self,name):
        """
        Method to fetch current os settings.
        """
        global Adapter_old_os_settings_list
        global Adapter_new_os_settings_list
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
        self.Net_ipv4_tcp_rmem = os_command(GET_NET_IPV4_TCP_RMEM).strip().split()[2].lstrip()
        self.Net_ipv4_tcp_wmem = os_command(GET_NET_IPV4_TCP_WMEM).strip().split()[2].lstrip()
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
       
    
    def set_recommended_os_settings(self):
        """
        Method to set the HPE recommended os settings.
        """
        if self.Recommended_Firewall_status == 'inactive (dead)':
            os_command(SET_FIREWALL_OFF.format('stop'))
        else:
            os_command(SET_FIREWALL_OFF.format('start'))
        if self.Recommended_IRQ_balance == 'inactive (dead)':
            os_command(SET_IRQBALANCE_OFF.format('stop'))
        else:
            os_command(SET_IRQBALANCE_OFF.format('start'))
        if self.Recommended_Ipv4_tcp_timestamps == 'Enable (1)':
            os_command(SET_IPV4_TCP_TIMESTAMPS.format('1'))
        else:
            os_command(SET_IPV4_TCP_TIMESTAMPS.format('0'))
        if self.Recommended_Ipv4_tcp_sack == 'Enable (1)':
            os_command(SET_IPV4_TCP_SACK.format('1'))
        else:
            os_command(SET_IPV4_TCP_SACK.format('0'))
        os_command(SET_ADAPTIVE_TX_TXUSECS_TXFRAMES)
        os_command(SET_CORE_NETDV_MAX_BACKLOG.format(self.Recommended_Netdv_max_backlog))
        os_command(SET_NET_CORE_RMEM_MAX.format(self.Recommended_Core_rmem_max))
        os_command(SET_NET_CORE_WMEM_MAX.format(self.Recommended_Core_wmem_max))
        os_command(SET_NET_CORE_RMEM_DEFAULT.format(self.Recommended_Core_rmem_default))
        os_command(SET_NET_CORE_WMEM_DEFAULT.format(self.Recommended_Core_wmem_drefault))
        os_command(SET_NET_CORE_OPTMEM_MAX.format(self.Recommended_Core_optmem_max))
        os_command(SET_NET_IPV4_TCP_RMEM.format(self.Recommended_Net_ipv4_tcp_rmem))
        os_command(SET_NET_IPV4_TCP_WMEM.format(self.Recommended_Net_ipv4_tcp_wmem))
        os_command(SET_IPV4_LOW_LATENCY.format(self.Recommended_Net_ipv4_tcp_low_latency))
        for bus_id in Bus_id_list:
            if bus_id.Network_if_name != 'Check_Driver': 
                os_command(SET_LRO_ON.format(bus_id.Network_if_name))                  
                os_command(SET_ADAPTIVE_TX_TXUSECS_TXFRAMES.format(bus_id.Network_if_name,self.Recommended_Tx_usecs)) 
                os_command(SET_ADAPTIVE_RX_RXUSECS_RXFRAMES.format(bus_id.Network_if_name,self.Recommended_Rx_usecs))
                os_command(SET_RING_PARAMETERS_TX_RX.format(bus_id.Network_if_name,self.Recommended_Ring_buffer_size_tx,self.Recommended_Ring_buffer_size_rx ))
                os_command(SET_COMBINED_QUEUE.format(bus_id.Network_if_name,self.Recommended_Combined_queue))
        
             
    def log_report_os_settings(self):
        """
        Method that generate report for os settings before making any recommended changes.
        """
        string = ''
        recommended = "  [ "+colors.yellow+"Recommended"+colors.END+" : "+colors.green
        if self.Firewall_status == self.Recommended_Firewall_status: 
            string += "    Firewall Status          :    "+self.Firewall_status+"\n"
        else:
            string += "    Firewall Status          :    "+self.Firewall_status+recommended+self.Recommended_Firewall_status+colors.END+" ]\n"
        if self.IRQ_balance == self.Recommended_IRQ_balance:
            string += "    IRQ Balance              :    "+self.IRQ_balance+"\n"
        else:
            string += "    IRQ Balance              :    "+self.IRQ_balance+recommended+self.Recommended_IRQ_balance+colors.END+" ]\n"
        if self.Ipv4_tcp_timestamps == self.Recommended_Ipv4_tcp_timestamps:
            string += "    TCP Timestamp            :    "+self.Ipv4_tcp_timestamps+"\n"
        else:
            string += "    TCP Timestamp            :    "+self.Ipv4_tcp_timestamps+recommended+self.Recommended_Ipv4_tcp_timestamps+colors.END+" ]\n"
        if self.Ipv4_tcp_sack == self.Recommended_Ipv4_tcp_sack:
            string += "    TCP Selective Acks       :    "+self.Ipv4_tcp_sack+"\n"
        else:
            string += "    TCP Selective Acks       :    "+self.Ipv4_tcp_sack+recommended+self.Recommended_Ipv4_tcp_sack+colors.END+" ]\n"
        if self.Netdv_max_backlog == self.Recommended_Netdv_max_backlog:
            string += "    Proc Input Queue         :    "+self.Netdv_max_backlog+"\n"
        else:
            string += "    Proc Input Queue         :    "+self.Netdv_max_backlog+recommended+self.Recommended_Netdv_max_backlog+colors.END+" ]\n"
        if self.Net_ipv4_tcp_low_latency == self.Recommended_Net_ipv4_tcp_low_latency:
            string += "    TCP IPv4 Low Latency     :    "+self.Net_ipv4_tcp_low_latency+"\n"
        else:
            string += "    TCP IPv4 Low Latency     :    "+self.Net_ipv4_tcp_low_latency+recommended+self.Recommended_Net_ipv4_tcp_low_latency+colors.END+" ]\n"
        string += colors.lblue+"    TCP Buffer Size"+colors.END+":\n"
        if self.Core_rmem_max == self.Recommended_Core_rmem_max:
            string += "        Core RMEM Max        :    "+self.Core_rmem_max+"\n"
        else:
            string += "        Core RMEM Max        :    "+self.Core_rmem_max+recommended+self.Recommended_Core_rmem_max+colors.END+" ]\n"
        
        if self.Core_wmem_max == self.Recommended_Core_wmem_max:
            string += "        Core WMEM Max        :    "+self.Core_wmem_max+"\n"
        else:
            string += "        Core WMEM Max        :    "+self.Core_wmem_max+recommended+self.Recommended_Core_wmem_max+colors.END+" ]\n"
        
        if self.Core_rmem_default == self.Recommended_Core_rmem_default:
            string += "        Core RMEM Default    :    "+self.Core_rmem_default+"\n"
        else: 
            string += "        Core RMEM Default    :    "+self.Core_rmem_default+recommended+self.Recommended_Core_rmem_default+colors.END+" ]\n"
        
        if self.Core_wmem_drefault == self.Recommended_Core_wmem_drefault:
            string += "        Core WMEM Default    :    "+self.Core_wmem_drefault+"\n"
        else:
            string += "        Core WMEM Default    :    "+self.Core_wmem_drefault+recommended+self.Recommended_Core_wmem_drefault+colors.END+" ]\n"
        
        if self.Core_optmem_max == self.Recommended_Core_optmem_max:
            string += "        Core OPTMEM Max      :    "+self.Core_optmem_max+"\n"
        else:
            string += "        Core OPTMEM Max      :    "+self.Core_optmem_max+recommended+self.Recommended_Core_optmem_max+colors.END+" ]\n"
            
        string += colors.lblue+"    TCP Memory Size"+colors.END+":\n"
        if self.Net_ipv4_tcp_rmem == self.Recommended_Net_ipv4_tcp_rmem:
            string += "        IPv4 RMEM            :    "+self.Net_ipv4_tcp_rmem+"\n"
        else:
            string += "        IPv4 RMEM            :    "+self.Net_ipv4_tcp_rmem+recommended+self.Recommended_Net_ipv4_tcp_rmem+colors.END+" ]\n"
        
        if self.Net_ipv4_tcp_wmem == self.Recommended_Net_ipv4_tcp_wmem:
            string += "        IPv4 WMEM            :    "+self.Net_ipv4_tcp_wmem+"\n"
        else:
            string += "        IPv4 WMEM            :    "+self.Net_ipv4_tcp_wmem+recommended+self.Recommended_Net_ipv4_tcp_wmem+colors.END+" ]\n"
        string += colors.lblue+"Mellanox Adapter OS Settings  "+colors.END+"["+colors.yellow+" HPE Recommended "+colors.END+"] \n"
        for index in range(len(Bus_id_list)):
            if Bus_id_list[index].Network_if_name == 'Check_Driver': 
                string += "    "+Bus_id_list[index].name+"    :   Check_Driver"+"\n"
            else:
                string += "    "+Adapter_os_setting_list[index].name+"\n"
                
                if Adapter_os_setting_list[index].LRO_ON == self.Recommended_LRO_ON:
                    string += "        LRO                  :    "+Adapter_os_setting_list[index].LRO_ON+"\n"
                else:
                    string += "        LRO                  :    "+Adapter_os_setting_list[index].LRO_ON+recommended+self.Recommended_LRO_ON+colors.END+" ]\n"
                
                if Adapter_os_setting_list[index].Rx_gro_hw == self.Recommended_Rx_gro_hw:
                    string += "        GRO                  :    "+Adapter_os_setting_list[index].Rx_gro_hw+"\n"
                else:
                    string += "        GRO                  :    "+Adapter_os_setting_list[index].Rx_gro_hw+recommended+self.Recommended_Rx_gro_hw+colors.END+" ]\n"
                if Adapter_os_setting_list[index].Rx_usecs == self.Recommended_Rx_usecs:
                    string += "        Adaptive Rx          :    "+Adapter_os_setting_list[index].Rx_usecs+"\n"
                else:
                    string += "        Adaptive Rx          :    "+Adapter_os_setting_list[index].Rx_usecs+recommended+self.Recommended_Rx_usecs+colors.END+" ]\n"
                if Adapter_os_setting_list[index].Tx_usecs == self.Recommended_Tx_usecs:
                    string += "        Adaptive Tx          :    "+Adapter_os_setting_list[index].Tx_usecs+"\n"
                else:
                    string += "        Adaptive Tx          :    "+Adapter_os_setting_list[index].Tx_usecs+recommended+ self.Recommended_Tx_usecs+colors.END+" ]\n"
                if Adapter_os_setting_list[index].Ring_buffer_size_rx[1] == self.Recommended_Ring_buffer_size_rx:
                    string += "        Ring_buffer_RX       :    "+Adapter_os_setting_list[index].Ring_buffer_size_rx[1]+"\n"
                else:
                    string += "        Ring_buffer_RX       :    "+Adapter_os_setting_list[index].Ring_buffer_size_rx[1]+recommended+ self.Recommended_Ring_buffer_size_rx+colors.END+" ]\n"
                if Adapter_os_setting_list[index].Ring_buffer_size_tx[1] == self.Recommended_Ring_buffer_size_tx:
                    string += "        Ring_buffer_TX       :    "+Adapter_os_setting_list[index].Ring_buffer_size_tx[1]+"\n"
                else:
                    string += "        Ring_buffer_TX       :    "+Adapter_os_setting_list[index].Ring_buffer_size_tx[1]+recommended+self.Recommended_Ring_buffer_size_tx+colors.END+" ]\n"
                if Adapter_os_setting_list[index].Combined_queue[1] == self.Recommended_Combined_queue:
                    string += "        Combined queue       :    "+Adapter_os_setting_list[index].Combined_queue[1]+"\n"
                else:
                    string += "        Combined queue       :    "+Adapter_os_setting_list[index].Combined_queue[1]+recommended+ self.Recommended_Combined_queue+colors.END+" ]\n"
        return string


    def log_set_os_settings(self , new):
        """
        Method that generates report after setting HPE recommended os settings.
        """
        global Adapter_old_os_settings_list
        global Adapter_new_os_settings_list
        string = ''
        note = "{}  [\033[33m Note \033[0m: Set from Current '{}' to HPE recommended '{}' ]"
        error = "{}  [\033[31m Error \033[0m: Failed to Set from Current '{}' to HPE recommended '{}' ]"
        if new.Firewall_status != self.Recommended_Firewall_status:
            string += "    Firewall Status         :    "+error.format(new.Firewall_status,new.Firewall_status,self.Recommended_Firewall_status)+"\n"
        elif self.Firewall_status == new.Firewall_status:
            string += "    Firewall Status         :    "+self.Firewall_status+"\n"
        else:
            string += "    Firewall Status         :    "+note.format(new.Firewall_status,self.Firewall_status,new.Firewall_status)+"\n"
        
        if self.Recommended_IRQ_balance != new.IRQ_balance:
            string += "    IRQ Balance             :    "+error.format(new.IRQ_balance,new.IRQ_balance,self.Recommended_IRQ_balance)+"\n"
        elif self.IRQ_balance == new.IRQ_balance:
            string += "    IRQ Balance             :    "+self.IRQ_balance+"\n"
        else:
            string += "    IRQ Balance             :    "+note.format(new.IRQ_balance,self.IRQ_balance,new.IRQ_balance)+"\n"
        
        if self.Recommended_Ipv4_tcp_timestamps != new.Ipv4_tcp_timestamps:
            string += "    TCP Timestamp           :    "+error.format(new.Ipv4_tcp_timestamps,new.Ipv4_tcp_timestamps,self.Recommended_Ipv4_tcp_timestamps)+"\n"        
        elif self.Ipv4_tcp_timestamps == new.Ipv4_tcp_timestamps:
            string += "    TCP Timestamp           :    "+self.Ipv4_tcp_timestamps+"\n"
        else:
            string += "    TCP Timestamp           :    "+note.format(new.Ipv4_tcp_timestamps,self.Ipv4_tcp_timestamps,new.Ipv4_tcp_timestamps)+"\n"
        
        if self.Recommended_Ipv4_tcp_sack != new.Ipv4_tcp_sack:
            string += "    TCP Selective Acks      :    "+error.format(new.Ipv4_tcp_sack,new.Ipv4_tcp_sack,self.Recommended_Ipv4_tcp_sack)+"\n"
        elif self.Ipv4_tcp_sack == new.Ipv4_tcp_sack:
            string += "    TCP Selective Acks      :    "+self.Ipv4_tcp_sack+"\n"
        else:
            string += "    TCP Selective Acks      :    "+note.format(new.Ipv4_tcp_sack,self.Ipv4_tcp_sack,new.Ipv4_tcp_sack)+"\n"
        
        if self.Recommended_Netdv_max_backlog != new.Netdv_max_backlog:
            string += "    Proc Input Queue        :    "+error.format(new.Netdv_max_backlog,new.Netdv_max_backlog,self.Recommended_Netdv_max_backlog)+"\n"
        elif self.Netdv_max_backlog == new.Netdv_max_backlog:
            string += "    Proc Input Queue        :    "+self.Netdv_max_backlog+"\n"
        else:
            string += "    Proc Input Queue        :    "+note.format(new.Netdv_max_backlog,self.Netdv_max_backlog,new.Netdv_max_backlog)+"\n"
        
        if self.Recommended_Net_ipv4_tcp_low_latency != new.Net_ipv4_tcp_low_latency:
            string += "    TCP Low Latency         :    "+error.format(new.Net_ipv4_tcp_low_latency,new.Net_ipv4_tcp_low_latency,self.Recommended_Net_ipv4_tcp_low_latency)+"\n"
        elif self.Net_ipv4_tcp_low_latency == new.Net_ipv4_tcp_low_latency:
            string += "    TCP Low Latency         :    "+self.Net_ipv4_tcp_low_latency+"\n"
        else:
            string += "    TCP Low Latency         :    "+note.format(new.Net_ipv4_tcp_low_latency,self.Net_ipv4_tcp_low_latency,new.Net_ipv4_tcp_low_latency)+"\n"
        
        string += colors.lblue+"    TCP Buffer Size"+colors.END+":\n"
        
        if self.Recommended_Core_rmem_max != new.Core_rmem_max:
            string += "        RMEM Max            :    "+error.format(new.Core_rmem_max,new.Core_rmem_max,self.Recommended_Core_rmem_max)+"\n"
        elif self.Core_rmem_max == new.Core_rmem_max:
            string += "        RMEM Max            :    "+self.Core_rmem_max+"\n"
        else:
            string += "        RMEM Max            :    "+note.format(new.Core_rmem_max,self.Core_rmem_max,new.Core_rmem_max)+"\n"
        
        if self.Recommended_Core_wmem_max != new.Core_wmem_max:
            string += "        WMEM Max            :    "+error.format(new.Core_wmem_max,new.Core_wmem_max,self.Recommended_Core_wmem_max)+"\n"
        elif self.Core_wmem_max == new.Core_wmem_max:
            string += "        WMEM Max            :    "+self.Core_wmem_max+"\n"
        else:
            string += "        WMEM Max            :    "+note.format(new.Core_wmem_max,self.Core_wmem_max,new.Core_wmem_max)+"\n"
        
        
        if self.Recommended_Core_rmem_default != new.Core_rmem_default:
            string += "        RMEM Default        :    "+error.format(new.Core_rmem_default, new.Core_rmem_default,self.Recommended_Core_rmem_default)+"\n"
        elif self.Core_rmem_default == new.Core_rmem_default:
            string += "        RMEM Default        :    "+self.Core_rmem_default+"\n"
        else:
            string += "        RMEM Default        :    "+note.format(new.Core_rmem_default, self.Core_rmem_default,new.Core_rmem_default)+"\n"
        
        if self.Recommended_Core_wmem_drefault != new.Core_wmem_drefault:
            string += "        WMEM Default        :    "+error.format(new.Core_wmem_drefault,new.Core_wmem_drefault,self.Recommended_Core_wmem_drefault)+"\n"
        elif self.Core_wmem_drefault == new.Core_wmem_drefault:
            string += "        WMEM Default        :    "+self.Core_wmem_drefault+"\n"
        else:
            string += "        WMEM Default        :    "+note.format(new.Core_wmem_drefault,self.Core_wmem_drefault,new.Core_wmem_drefault)+"\n"
        
        if self.Recommended_Core_optmem_max != new.Core_optmem_max:
            string += "        OPTMEM Max          :    "+error.format(new.Core_optmem_max,new.Core_optmem_max,self.Recommended_Core_optmem_max)+"\n"
        elif self.Core_optmem_max == new.Core_optmem_max:
            string += "        OPTMEM Max          :    "+self.Core_optmem_max+"\n"
        else:   
            string += "        OPTMEM Max          :    "+note.format(new.Core_optmem_max,self.Core_optmem_max,new.Core_optmem_max)+"\n"
        
        string += colors.lblue+"    TCP Memory Size"+colors.END+":\n"
        
        if self.Recommended_Net_ipv4_tcp_rmem != new.Net_ipv4_tcp_rmem:    
            string += "        TCP RMEM            :    "+error.format(new.Net_ipv4_tcp_rmem,new.Net_ipv4_tcp_rmem,self.Recommended_Net_ipv4_tcp_rmem)+"\n"
        elif self.Net_ipv4_tcp_rmem == new.Net_ipv4_tcp_rmem:
            string += "        TCP RMEM            :    "+self.Net_ipv4_tcp_rmem+"\n"
        else:
            string += "        TCP RMEM            :    "+note.format(new.Net_ipv4_tcp_rmem,self.Net_ipv4_tcp_rmem,new.Net_ipv4_tcp_rmem)+"\n"
        
        if self.Recommended_Net_ipv4_tcp_wmem != new.Net_ipv4_tcp_wmem:
            string += "        TCP WMEM            :    "+error.format(new.Net_ipv4_tcp_wmem,new.Net_ipv4_tcp_wmem,self.Recommended_Net_ipv4_tcp_wmem)+"\n"
        if self.Net_ipv4_tcp_wmem == new.Net_ipv4_tcp_wmem:
            string += "        TCP WMEM            :    "+self.Net_ipv4_tcp_wmem+"\n"
        else:  
            string += "        TCP WMEM            :    "+note.format(new.Net_ipv4_tcp_wmem,self.Net_ipv4_tcp_wmem,new.Net_ipv4_tcp_wmem)+"\n"
        
        string += colors.lblue+"Mellanox Adapter OS Settings  "+colors.END+"["+colors.yellow+" HPE Recommended "+colors.END+"] :\n"
        
        for index in range(len(Bus_id_list)):
            
            if Bus_id_list[index].Network_if_name == 'Check_Driver': 
                string += "    "+Bus_id_list[index].name+"    :   Check_Driver\n"
            else:
                string += "    "+Adapter_old_os_settings_list[index].name+"\n"
                
                if self.Recommended_LRO_ON != Adapter_new_os_settings_list[index].LRO_ON:
                    string += "        LRO                 :    "+error.format(Adapter_new_os_settings_list[index].LRO_ON, Adapter_new_os_settings_list[index].LRO_ON , self.Recommended_LRO_ON)+"\n"
                elif Adapter_old_os_settings_list[index].LRO_ON == Adapter_new_os_settings_list[index].LRO_ON:
                    string += "        LRO                 :    "+Adapter_old_os_settings_list[index].LRO_ON+"\n"
                else:
                    string += "        LRO                 :    "+note.format(Adapter_new_os_settings_list[index].LRO_ON, Adapter_old_os_settings_list[index].LRO_ON , Adapter_new_os_settings_list[index].LRO_ON)+"\n"    

                if self.Recommended_Rx_gro_hw != Adapter_new_os_settings_list[index].Rx_gro_hw:
                    string += "        GRO                 :    "+error.format(Adapter_new_os_settings_list[index].Rx_gro_hw , Adapter_new_os_settings_list[index].Rx_gro_hw ,self.Recommended_Rx_gro_hw)+"\n"
                elif Adapter_old_os_settings_list[index].Rx_gro_hw == Adapter_new_os_settings_list[index].Rx_gro_hw:
                    string += "        GRO                 :    "+Adapter_old_os_settings_list[index].Rx_gro_hw+"\n"
                else:
                    string += "        GRO                 :    "+note.format(Adapter_new_os_settings_list[index].Rx_gro_hw , Adapter_old_os_settings_list[index].Rx_gro_hw , Adapter_new_os_settings_list[index].Rx_gro_hw)+"\n"
                
                if self.Recommended_Rx_usecs != Adapter_new_os_settings_list[index].Rx_usecs:
                    string += "        Adaptive Rx         :    "+error.format(Adapter_new_os_settings_list[index].Rx_usecs, Adapter_new_os_settings_list[index].Rx_usecs,self.Recommended_Rx_usecs)+"\n"
                elif Adapter_old_os_settings_list[index].Rx_usecs == Adapter_new_os_settings_list[index].Rx_usecs:
                    string += "        Adaptive Rx         :    "+Adapter_old_os_settings_list[index].Rx_usecs+"\n"
                else:
                    string += "        Adaptive Rx         :    "+note.format( Adapter_new_os_settings_list[index].Rx_usecs, Adapter_old_os_settings_list[index].Rx_usecs, Adapter_new_os_settings_list[index].Rx_usecs)+"\n"
                    
                if self.Recommended_Tx_usecs != Adapter_new_os_settings_list[index].Tx_usecs:
                    string += "        Adaptive Tx         :    "+error.format(Adapter_new_os_settings_list[index].Tx_usecs , Adapter_new_os_settings_list[index].Tx_usecs,self.Recommended_Tx_usecs)+"\n"  
                elif Adapter_old_os_settings_list[index].Tx_usecs == Adapter_new_os_settings_list[index].Tx_usecs:
                    string += "        Adaptive Tx         :    "+Adapter_old_os_settings_list[index].Tx_usecs+"\n"
                else:
                    string += "        Adaptive Tx         :    "+note.format(Adapter_new_os_settings_list[index].Tx_usecs , Adapter_old_os_settings_list[index].Tx_usecs, Adapter_new_os_settings_list[index].Tx_usecs)+"\n"
                
                if self.Recommended_Ring_buffer_size_rx != Adapter_new_os_settings_list[index].Ring_buffer_size_rx[1]:
                    string += "        Ring_buffer_RX      :    "+error.format(Adapter_new_os_settings_list[index].Ring_buffer_size_rx[1] , Adapter_new_os_settings_list[index].Ring_buffer_size_rx[1], self.Recommended_Ring_buffer_size_rx)+"\n"
                elif Adapter_old_os_settings_list[index].Ring_buffer_size_rx[1] == Adapter_new_os_settings_list[index].Ring_buffer_size_rx[1]:
                    string += "        Ring_buffer_RX      :    "+Adapter_old_os_settings_list[index].Ring_buffer_size_rx[1]+"\n"
                else:
                    string += "        Ring_buffer_RX      :    "+note.format(Adapter_new_os_settings_list[index].Ring_buffer_size_rx[1] , Adapter_old_os_settings_list[index].Ring_buffer_size_rx[1], Adapter_new_os_settings_list[index].Ring_buffer_size_rx[1])+"\n"
                
                if self.Recommended_Ring_buffer_size_tx != Adapter_new_os_settings_list[index].Ring_buffer_size_tx[1]:
                    string += "        Ring_buffer_TX      :    "+error.format(Adapter_new_os_settings_list[index].Ring_buffer_size_tx[1] , Adapter_new_os_settings_list[index].Ring_buffer_size_tx[1],self.Recommended_Ring_buffer_size_tx)+"\n"                
                elif Adapter_old_os_settings_list[index].Ring_buffer_size_tx[1] == Adapter_new_os_settings_list[index].Ring_buffer_size_tx[1]:
                    string += "        Ring_buffer_TX      :    "+Adapter_old_os_settings_list[index].Ring_buffer_size_tx[1]+"\n"
                else:
                    string += "        Ring_buffer_TX      :    "+note.format(Adapter_new_os_settings_list[index].Ring_buffer_size_tx[1] , Adapter_old_os_settings_list[index].Ring_buffer_size_tx[1],Adapter_new_os_settings_list[index].Ring_buffer_size_tx[1])+"\n"
                
                if self.Recommended_Combined_queue == Adapter_new_os_settings_list[index].Combined_queue[1]:
                    string += "        Combined queue      :    "+note.format(Adapter_new_os_settings_list[index].Combined_queue[1] , Adapter_new_os_settings_list[index].Combined_queue[1], self.Recommended_Combined_queue)+"\n"
                if Adapter_old_os_settings_list[index].Combined_queue[1] == Adapter_new_os_settings_list[index].Combined_queue[1]:
                    string += "        Combined queue      :    "+Adapter_old_os_settings_list[index].Combined_queue[1]+"\n"
                else:
                    string += "        Combined queue      :    "+note.format(Adapter_new_os_settings_list[index].Combined_queue[1] , Adapter_old_os_settings_list[index].Combined_queue[1], Adapter_new_os_settings_list[index].Combined_queue[1])+"\n"
        
        return string


class bios_settings:
    """
    Class containing details about bios settings.
    """
    def __init__(self):
        self.WorkloadProfile = "Unknown"
        self.ProcHyperthreading = "Unknown"
        self.Recommended_WorkloadProfile = "Unknown"
        self.Recommended_ProcHyperthreading = "Unknown"
    
    
    def get_hpe_bios_settings(self):
        result = os_command(GET_BIOS_SETTINGS)
        #print(result)
        with open('config.txt','r') as file:
            lines = file.readlines()
            for line in lines:
                words = line.split('=')
                for item in result.strip().split('\n'):
                    if 'WorkloadProfile' in item and 'WorkloadProfile' in line:
                        self.WorkloadProfile = item.split('=')[-1].strip()
                        self.Recommended_WorkloadProfile = words[1].strip().replace('"','')
                    elif 'ProcHyperthreading' in item and 'ProcHyperthreading' in line:
                        self.ProcHyperthreading = item.split('=')[-1].strip()
                        self.Recommended_ProcHyperthreading = words[1].strip()        
    def set_intel_bios_Settings(self):
        """
        Method that sets the intel specific bios details
        """
        pass      
            
                    
    def set_amd_bios_setings(self):
        """
        Method that sets the AMD specific bios settings
        """
        pass
    

    def set_hpe_bios_settings(self):
        """
        Method that sets HPE recommended bios settings.
        """
        #print(os_command(GET_TYPE_OF_PROCESSOR))
        if 'Intel' in os_command(GET_TYPE_OF_PROCESSOR):
            with open('config.txt','r') as file:
                lines = file.readlines()
                for line in lines:
                    words = line.strip().split('=')
                    #print(words)
                    #print(self.__dict__)
                    if words[0][0]=='#':
                        continue
                    elif self.__dict__[words[0]] != 'Unknown':
                        #print('exec '+line)
                        os_command("ilorest set "+line.strip()+" --select Bios. --commit")    
        

    def log_report_bios_settings(self):
        """
        Method that generates report before making the recommended changes.
        """
        string = ''
        
        with open('config.txt','r') as file:
            lines = file.readlines()
            for line in lines:
                words = line.strip().split('=')
                if lines[0]=='#':
                    continue
                elif words[0] in self.__dict__.keys():
                    current = self.__dict__[words[0]]
                    if current != 'Unknown':
                        indent = "{:>"+str(28-len(words[0]))+"}"
                        if words[1].replace('"','')==current:
                            string += "    "+words[0]+indent.format(':  ')+current+"\n"
                        else:  
                            string += "    "+words[0]+indent.format(':  ')+current+"  [ "+colors.yellow+"Recommended"+colors.END+" : "+colors.green+words[1]+colors.END+" ]\n"
        return string
            
        
    def log_set_bios_settings(self,new):
        """
        Method that generates report after the recommended changes.
        """
        note = "{}  [\033[33m Note \033[0m: Set from Current '{}' to HPE recommended '{}' ]"
        error = "{}  [\033[31m Error \033[0m: Failed to set HPE recommended '{}' from current '{}' setting ]"
        string = ''
        if self.WorkloadProfile == new.WorkloadProfile and self.WorkloadProfile != self.Recommended_WorkloadProfile:
            string += "    WorkloadProfile              :    "+error.format(self.WorkloadProfile,self.Recommended_WorkloadProfile,self.WorkloadProfile)+"\n"
        elif self.WorkloadProfile == new.WorkloadProfile:
            string += "    WorkloadProfile              :    "+self.WorkloadProfile+"\n"
        else:
            string += "    WorkloadProfile              :    "+note.format(new.WorkloadProfile,self.WorkloadProfile,new.WorkloadProfile)+"\n"
        if self.ProcHyperthreading == new.ProcHyperthreading and self.ProcHyperthreading != self.Recommended_ProcHyperthreading:
            string += "    ProcHyperthreading           :    "+error.format(self.ProcHyperthreading,self.Recommended_ProcHyperthreading,self.ProcHyperthreading)+"\n"
        elif self.ProcHyperthreading == new.ProcHyperthreading:
            string += "    ProcHyperthreading           :    "+self.ProcHyperthreading+"\n"
        else:
            string += "    ProcHyperthreading           :    "+note.format(new.ProcHyperthreading,self.ProcHyperthreading,new.ProcHyperthreading)+"\n"
        return string


def get_deailed_log():
    """
    For logging all the required commands.
    """
    string = ''
    
    for command in COMMANDS_FOR_LOG_FILE:
        if command == GET_CHIPSET:
            for bus_id in Bus_id_list:
                string += colors.lblue+"output of 'lspci -vvvs {}' command".format(bus_id.name)+ colors.END+" :\n"
                string += os_command(GET_CHIPSET.format(bus_id.name))+"\n"
        else:
            string += colors.lblue+"output of '"+command+"' command"+ colors.END+" :\n"
            string += os_command(command)+"\n"
    return string
 

def Generate_report():
    global Adapter_os_setting_list
    Server_manufacturer_name = os_command(GET_SERVER_MANUFACTURER_NAME).strip()
    Sever_product_name = os_command(GET_SERVER_PRODUCT_NAME).split(':')[-1].strip()  
    Server = server_details()
    Os_details = Server.get_os_details()
    Bios_details = Server.get_bios_details()
    Processor_details = Server.get_processor_details()
    Memory_details = Server.get_memory_details()
    Os_settings = os_settings()
    Os_settings.get_os_settings(Adapter_os_setting_list)
    Os_settings_details = Os_settings.log_report_os_settings()
    Bios_settings = bios_settings()
    Bios_settings.get_hpe_bios_settings()
    Bios_settings_details = Bios_settings.log_report_bios_settings()
    
    string = colors.bblue+"Collecting {} Processor, BIOS, OS and Mellanox Adapter report".format(Server_manufacturer_name+" "+Sever_product_name)+colors.END+"\n\n"
    string += Os_details+"\n"
    string += Bios_details+"\n"
    string += Processor_details+"\n"
    string += Memory_details+"\n"
    string += Mlnx_device_details+"\n"
    string += colors.lblue+"OS Settings  "+colors.END+"["+colors.yellow+" HPE Recommended "+colors.END+"] :\n"
    string += Os_settings_details+"\n"
    string += colors.lblue+"BIOS Settings  "+colors.END+"["+colors.yellow+" HPE Recommended "+colors.END+"] :\n"
    string += Bios_settings_details+"\n"
    return string


def HPE_recommended_os_settings():
    global Adapter_old_os_settings_list
    global Adapter_new_os_settings_list
    Old_os_settings = os_settings()
    Old_os_settings.get_os_settings(Adapter_old_os_settings_list)
    Old_os_settings.set_recommended_os_settings()
    New_os_settings = os_settings()
    New_os_settings.get_os_settings(Adapter_new_os_settings_list)
    string = colors.lblue+"OS Settings  "+colors.END+"["+colors.yellow+" HPE Recommended "+colors.END+"] :\n"
    string += Old_os_settings.log_set_os_settings(New_os_settings)+"\n"
    return string

def HPE_recommended_bios_settings():
    Old_bios = bios_settings()
    Old_bios.get_hpe_bios_settings()
    Old_bios.set_hpe_bios_settings()
    New_bios = bios_settings()
    New_bios.get_hpe_bios_settings()
    string = colors.lblue+"BIOS Settings  "+colors.END+"["+colors.yellow+" HPE Recommended "+colors.END+"] :\n"
    string += Old_bios.log_set_bios_settings(New_bios)
    return string


def main():
    global Mlnx_device_details
    if options.help:
        print(help_message)
        sys.exit()
        
    file_name = "/tmp/hpefabrictuner_"+get_date_and_time()+".log"
    file = open(file_name,'w')
    file.close()
    Mlnx_device_details = get_mlnx_device_details()
    """for item in Bus_id_list:
        print(item.__dict__)"""
    if options.report:
        report = Generate_report()
        write_info_to_file(file_name,report,True)
        
    elif options.os:
        Os_settings_details = HPE_recommended_os_settings()
        write_info_to_file(file_name,Os_settings_details,True)
        print(colors.yellow+"Note"+colors.END+": To apply changes, request to reboot the server.\n\n")
    
    elif options.hpe_bios:
        Bios_settings_details = HPE_recommended_bios_settings()
        write_info_to_file(file_name,Bios_settings_details,True)
        print(colors.yellow+"Note"+colors.END+": To apply changes, request to reboot the server.\n\n")
        
    else:
        Os_settings_details = HPE_recommended_os_settings()
        Bios_settings_details = HPE_recommended_bios_settings()
        result = Os_settings_details + "\n" + Bios_settings_details
        write_info_to_file(file_name,result,True)
        print(colors.yellow+"Note"+colors.END+": To apply changes, request to reboot the server.\n")
        
        
    Detailed_log = get_deailed_log()
    write_info_to_file(file_name,Detailed_log,False)

    print(colors.yellow+"INFO"+colors.END+": Detailed System info file: "+file_name+"\n")

if __name__=='__main__':
    
    Bus_id_list = []
    Adapter_old_os_settings_list = []
    Adapter_new_os_settings_list = []
    Adapter_os_setting_list = []
    Mlnx_device_details=''
    parser = OptionParser(add_help_option=False)
    options , logger = initialize()
    
    main()