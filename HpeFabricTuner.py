"""#!usr/bin/python2.7"""
# -*- coding: utf-8 -*-

import os
import subprocess
import time
import sys
import paramiko



GET_OS_NAME             = "cat /etc/os-release | grep 'PRETTY_NAME'"
GET_KERNAL_VERSION      = "uname -r"
GET_BIOS_RELEASE_DATE   = "dmidecode -t bios | grep 'Release Date:' | awk '{print $3}'"
GET_BIOS_VERSION        = "dmidecode -t bios | grep 'Version:' | awk '{print $2}'"
GET_PROCESSOR_NAME      = "dmidecode -t processor | grep 'Version'"
GET_SOCKETS_COUNT       = "dmidecode -t processor | grep 'Version'"
GET_CORE_COUNT          = "dmidecode -t processor | grep 'Core Count'"
GET_THREAD_COUNT        = "dmidecode -t processor | grep 'Thread Count'"
GET_MAX_SPEED           = "dmidecode -t processor | grep 'Max Speed'"
GET_NUMA_NODE_COUNT     = "lscpu | grep NUMA"
GET_NO_OF_DIMMS         = "dmidecode -t memory | grep 'Number Of Devices:'"
GET_DIMM_SIZE           = "dmidecode -t memory | grep '^\s*Size:'"
GET_TOTAL_MEMORY        = "free | grep Mem | awk '{print $2}'"
GET_MEMORY_SPEED        = "dmidecode -t memory | grep '^\s*Speed:'"
GET_MEMORY_TYPE         = "dmidecode -t memory | grep '^\s*Type:'"
GET_MLNX_DEVICES        = "lspci | grep -i mell"
GET_NUMA_NODE           = "lspci -vvvs {0} | grep 'NUMA node:' | awk '{1}'"
GET_PART_NUMBER         = "lspci -vvvs {0} | grep -i 'Part number:' | awk '{1}'"
GET_PRODUCT_NAME        = "lspci -vvvs {0} | grep -i 'Product name:'"
GET_PCI_SLOT            = "lspci -vvvs {0} | grep -i 'Physical slot:' | awk '{1}'"
GET_LINK_SPEED          = "lspci -vvvs {0} | grep -i 'LnkSta:' | awk '{1}'"
GET_LINK_WIDTH          = "lspci -vvvs {0} | grep -i 'LnkSta:' | awk '{1}'"
GET_INTERFACE_NAME      = "ls -l /sys/class/infiniband/* | grep {0}"
GET_NW_INTERFCAE_NAME   = "ls -l /sys/class/net/* | grep '{0}'"
GET_CHIPSET             = "lspci -vvvs {0} | grep '{0}'"
GET_FW_VERSION          = "ibstat {0} | grep 'Firmware version:' | awk '{1}'"
GET_PSID                = "~/HpeFabricsTuner/mstflint -d {0} q | grep PSID: | awk '{1}'"
GET_FIREWALL_STATUS     = "systemctl status firewalld | grep -i Active"
GET_IRQBALANCE_STATUS   = "systemctl status irqbalance | grep -i Active"


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
    val=0
    dictionary = {1:'MB',
                  2:'GB',
                  3:'TB'}
    while Total_memory>999:
        Total_memory//=1000
        val+=1
    Total_memory = str(Total_memory)+dictionary[val]
    temp = Dimm_size.split()[1].strip()
    Dimm_size = int(Dimm_size.split()[0])
    val = 0
    while Dimm_size>999:
        Dimm_size//=1000
        val+=1
    if temp in dictionary.values():
        for item in dictionary.keys():
            if temp == dictionary[item]:
                add_on = dictionary[item+val]
                break
    Dimm_size = str(Dimm_size)+" "+add_on
    return Total_memory , Dimm_size


def get_os_details():
    Os_name = os_command(GET_OS_NAME).strip().split('=')[-1]
    Os_kernel_version = os_command(GET_KERNAL_VERSION).strip()
    print("\nOS : {} Kernel version is {} \n".format(Os_name,Os_kernel_version))


def get_bios_details():
    Bios_release_date = os_command(GET_BIOS_RELEASE_DATE).strip()
    Bios_version =  os_command(GET_BIOS_VERSION).strip()
    print("Bios : {} {} \n".format(Bios_version,Bios_release_date))

    
def get_processor_details():
    processor_name = os_command(GET_PROCESSOR_NAME).split('\n')[0].split(':')[-1]
    Socket_count = len(os_command(GET_SOCKETS_COUNT).strip().split('\n'))
    Core_count = os_command(GET_CORE_COUNT).split('\n')[0].split(':')[-1].strip()
    Thread_count = os_command(GET_THREAD_COUNT).split('\n')[0].split(':')[-1].strip()
    Max_speed = os_command(GET_MAX_SPEED).split('\n')[0].split(':')[-1].strip()
    NUMA_node =  os_command(GET_NUMA_NODE_COUNT).strip().split('\n')[0].split(':')[-1].strip()
    print("Processor : {}, Socket#{}, Core#{} ,Thread#{}, MaxSpeed#{}, NUMA_NODE(S)#{} \n".format(processor_name,Socket_count,Core_count,Thread_count,Max_speed,NUMA_node))


def get_memory_details():
    count=0
    for item in os_command(GET_NO_OF_DIMMS).strip().split('\n'):
        count += int(item.strip().split(':')[-1])
    No_of_dimms = count
    count = 0
    
    for item in os_command(GET_DIMM_SIZE).strip().split('\n'):
        if 'No Module Installed' not in item:
            Dimm_size = item.strip().split(':')[-1].strip()
            count +=1
            
    Total_memory = os_command(GET_TOTAL_MEMORY).strip()
    Total_memory, Dimm_size = conversion(Total_memory,Dimm_size)
    No_of_active_dimms = count
    
    for item in os_command(GET_MEMORY_SPEED).strip().split('\n'):
        if 'Unknown' not in item:
            Dimm_speed = item.strip().split(':')[-1]
            break
        
    for item in os_command(GET_MEMORY_TYPE).strip().split('\n'):
        if 'Type Detail' not in item and 'Other' not in item:
            Dimm_type = item.strip().split(':')[-1]
            break
        
    print("Memory : Total Memory#{}, PerDIMM#{} {} {}, Populated DIMM's#{}\n".format(Total_memory,Dimm_size,Dimm_type,Dimm_speed,No_of_active_dimms))


def get_mlnx_device_details():
    mellanox_devices = os_command(GET_MLNX_DEVICES)
    mellanox_devices_list = mellanox_devices.strip().split('\n')
    temp_list = [item.split()[0] for item in mellanox_devices_list]
    bus_id_list = [temp_list[0]]
    
    for elem in range(1,len(temp_list)):
        if temp_list[elem][:2]!=temp_list[elem-1][:2]:
            bus_id_list.append(temp_list[elem])
            
    print("Mellanox Devices :")
    for bus_id in bus_id_list:
        Physical_slot = os_command(GET_PCI_SLOT.format(bus_id,'{print $3}')).strip()
        if Physical_slot == '':
            Physical_slot = 'LOM'
        Part_number = os_command(GET_PART_NUMBER.format(bus_id,'{print $4}')).strip()
        Product_name = os_command(GET_PRODUCT_NAME.format(bus_id)).strip().split(':')[-1]
        Link_speed = os_command(GET_LINK_WIDTH.format(bus_id,'{print $3}')).strip()
        Link_width = os_command(GET_LINK_WIDTH.format(bus_id,'{print $5}')).strip()
        NUMA_node = os_command(GET_NUMA_NODE.format(bus_id,'{print $3}')).strip()
        Chipset = os_command(GET_CHIPSET.format(bus_id)).strip().split()[-1]
        if 'Connect' not in Chipset:
            temp = os_command(GET_CHIPSET.format(bus_id)).strip().split()
            Chipset = temp[-2]+" "+temp[-1]
        Interface_name = os_command(GET_INTERFACE_NAME.format(bus_id)).strip().split('/')[-1]
        #print(Interface_name)
        FW_version = os_command(GET_FW_VERSION.format(Interface_name,'{print $3}')).strip()
        if Interface_name=='':
            Interface_name = 'Check_Driver'
        Network_if_name = os_command(GET_NW_INTERFCAE_NAME.format(bus_id)).strip().split('/')[-1]
        if Network_if_name=='':
            Network_if_name = 'Check_Driver'
        PSID = os_command(GET_PSID.format(bus_id,'{print $2}')).strip()
        
        print("{} {} FW#{} PCISlot#{} NUMAnode#{} Lw#{} Ls#{} P/N#{} PSID#{} {} {} {}".format(bus_id,Chipset,FW_version,Physical_slot,NUMA_node,Link_width,Link_speed,Part_number,PSID,Interface_name,Network_if_name,Product_name))
    

def log():
    #lscpu_data = os_command("lscpu")
    #cpu_info = os_command("cat /proc/cpuinfo")
    #print(cpu_info)
    """file = open('log.txt','w')
    file.close()"""
    """with open("log.txt","a") as file:
        file.write('command = "lspcu"\n')
        file.write(lscpu_data+"\n\n")
        file.write('command = "cat /proc/cpuinfo"\n')
        file.write(cpu_info+"\n\n")
        file.write('command = "lspci | grep -i mell"\n')
        file.write(mellanox_devices+"\n\n")
    print("Collected detailed system info to <>.txt")"""


def get_os_settings():
    Firewall_status = os_command(GET_FIREWALL_STATUS).strip().split(':')[-1]
    IRQ_balance = os_command(GET_IRQBALANCE_STATUS).strip().split(':')[-1]

if __name__=='__main__':
    
    if len(sys.argv)==2:
        
        if sys.argv[1]=='--help' or sys.argv[1]=='-h':
            print("\n -v, --version "+":".rjust(6)+"  print tool version and exit [default False]\
                \n -d, --debug "+":".rjust(8)+"  Capture all the report info and save it as a tar ball \
                \n -r, --report "+":".rjust(7)+"  Report HW/BIOS/OS status\
                \n -b, --hpe_bios "+":".rjust(5)+"  Set HPE recommended BIOS settings \
                \n -a, --arch_bios "+":".rjust(4)+"  Set processor vendor specific AMD/Intel/ARM recommended BIOS settings \
                \n -s, --os "+":".rjust(11)+"  Set HPE recommended OS settings \
                \n -i, --ilo "+":".rjust(10)+"  iLO IP to do remote BIOS update \
                \n -p, --password "+":".rjust(5)+"  iLO password while remote BIOS update \
                \n -u, --username "+":".rjust(5)+"  iLO username while remote BIOS update\
                \n -pr, --profile "+":".rjust(5)+"  Set choose from below list BIOS profile \
                \n  "+' '.rjust(24)+"['HIGH_THROUGHPUT',\
                \n  "+' '.rjust(24)+"'IP_FORWARDING_MULTI_STREAM_THROUGHPUT',\
                \n  "+' '.rjust(24)+"'IP_FORWARDING_MULTI_STREAM_PACKET_RATE', \
                \n  "+' '.rjust(24)+"'IP_FORWARDING_MULTI_STREAM_0_LOSS', \
                \n  "+' '.rjust(24)+"'IP_FORWARDING_SINGLE_STREAM', \
                \n  "+' '.rjust(24)+"'IP_FORWARDING_SINGLE_STREAM_0_LOSS', \
                \n  "+' '.rjust(24)+"'IP_FORWARDING_SINGLE_STREAM_SINGLE_PORT', \
                \n  "+' '.rjust(24)+"'LOW_LATENCY_VMA','MULTICAST']".rjust(22)+"\n \
                \n Examples: \
                \n The following are the standard usage of the tool. \
	            \n - 'hpefabrictuner'                      #Set both HPE recommended BIOS and OS tunings.\
 	            \n - 'hpefabrictuner --arch_bios'          #Set only AMD/Intel/ARM recommended BIOS settings.\
	            \n - 'hpefabrictuner –-hpe_bios'           #Set only HPE recommended BIOS settings.\
	            \n - 'hpefabrictuner –-os'                 #Set only HPE recommended OS tuning.\
	            \n - 'hpefabrictuner –-report'             #Report detailed report on Hardware/BIOS/OS \
	            \n - 'hpefabrictuner –-debug'              #Capture all the report info and save it as a tar ball\n")

        elif sys.argv[1]=='--report' or sys.argv[1]=='-r':
            
            get_os_details()
            
            get_bios_details()

            get_processor_details()
            
            get_memory_details()

            get_mlnx_device_details()


            



   