"""#!usr/bin/python2.7"""
# -*- coding: utf-8 -*-

import os
import subprocess
import time
import sys
import paramiko

Bus_id_list = []


GET_OS_NAME                     = "cat /etc/os-release | grep 'PRETTY_NAME'"
GET_KERNAL_VERSION              = "uname -r"
GET_BIOS_RELEASE_DATE           = "dmidecode -t bios | grep 'Release Date:' | awk '{print $3}'"
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
GET_CHIPSET                     = "lspci -vvvs {0} | grep '{0}'"
GET_FW_VERSION                  = "ibstat {0} | grep 'Firmware version:' | awk '{1}'"
GET_PSID                        = "~/HpeFabricsTuner/mstflint -d {0} q | grep PSID: | awk '{1}'"
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
GET_NET_CORE_OPTMEM_MAX         = "sysctl -x net.core.optmem_max | awk '{print $3}'"
GET_NET_IPV4_TCP_RMEM           = "sysctl -x net.ipv4.tcp_rmem"
GET_NET_IPV4_TCP_WMEM           = "sysctl -x net.ipv4.tcp_wmem"
GET_NET_IPV4_TCP_LOW_LATENCY    = "sysctl -x net.ipv4.tcp_low_latency | awk '{print $3}'"



class adapter_details:
    name = ''
    Physical_slot = ''
    Chipset = ''
    Part_number = ''
    Product_name = ''
    Link_speed = ''
    Link_width = ''
    Interface_name = ''
    Network_if_name = ''
    NUMA_node = ''
    PSID = ''
    FW_version = ''
    
    LRO_ON = ''
    Rx_gro_hw = ''
    Rx_usecs = ''
    Tx_usecs = ''
    
    Ring_parameters = ''
    combined_queue = ''




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

def get_Bus_id_list():
    global Bus_id_list
    mellanox_devices = os_command(GET_MLNX_DEVICES)
    mellanox_devices_list = mellanox_devices.strip().split('\n')
    temp_list = [ item.split()[0] for item in mellanox_devices_list]
    
    for elem in range(1,len(temp_list)):
        if temp_list[elem][:2]!=temp_list[elem-1][:2]:
            temp = adapter_details()
            temp.name = temp_list[elem]
            Bus_id_list.append(temp)
    print(Bus_id_list)


def get_mlnx_device_details():
    for bus_id in Bus_id_list:
        bus_id.Physical_slot = os_command(GET_PCI_SLOT.format(bus_id.name,'{print $3}')).strip()
        if bus_id.Physical_slot == '':
            bus_id.Physical_slot = 'LOM'
        bus_id.Part_number = os_command(GET_PART_NUMBER.format(bus_id.name,'{print $4}')).strip()
        bus_id.Product_name = os_command(GET_PRODUCT_NAME.format(bus_id.name)).strip().split(':')[-1]
        bus_id.Link_speed = os_command(GET_LINK_WIDTH.format(bus_id.name,'{print $3}')).strip()
        bus_id.Link_width = os_command(GET_LINK_WIDTH.format(bus_id.name,'{print $5}')).strip()
        bus_id.NUMA_node = os_command(GET_NUMA_NODE.format(bus_id.name,'{print $3}')).strip()
        bus_id.Chipset = os_command(GET_CHIPSET.format(bus_id.name)).strip().split()[-1]
        if 'Connect' not in bus_id.Chipset:
            temp = os_command(GET_CHIPSET.format(bus_id.name)).strip().split()
            bus_id.Chipset = temp[-2]+" "+temp[-1]
        bus_id.Interface_name = os_command(GET_INTERFACE_NAME.format(bus_id.name)).strip().split('/')[-1]
        #print(Interface_name)
        bus_id.FW_version = os_command(GET_FW_VERSION.format(bus_id.Interface_name,'{print $3}')).strip()
        if bus_id.Interface_name=='':
            bus_id.Interface_name = 'Check_Driver'
        bus_id.Network_if_name = os_command(GET_NW_INTERFCAE_NAME.format(bus_id.name)).strip().split('/')[-1]
        if bus_id.Network_if_name =='':
            bus_id.Network_if_name = 'Check_Driver'
        bus_id.PSID = os_command(GET_PSID.format(bus_id.name,'{print $2}')).strip()


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


class report:


    def get_os_details(self):
        self.Os_name = os_command(GET_OS_NAME).strip().split('=')[-1]
        self.Os_kernel_version = os_command(GET_KERNAL_VERSION).strip()


    def log_to_console_os_details(self):
        print("\nOS : {} Kernel version is {} \n".format(self.Os_name,self.Os_kernel_version))


    def get_bios_details(self):
        self.Bios_release_date = os_command(GET_BIOS_RELEASE_DATE).strip()
        self.Bios_version =  os_command(GET_BIOS_VERSION).strip()
        

    def log_to_console_bios_details(self):
        print("Bios : {} {} \n".format(self.Bios_version,self.Bios_release_date))

        
    def get_processor_details(self):
        self.processor_name = os_command(GET_PROCESSOR_NAME).split('\n')[0].split(':')[-1]
        self.Socket_count = len(os_command(GET_SOCKETS_COUNT).strip().split('\n'))
        self.Core_count = os_command(GET_CORE_COUNT).split('\n')[0].split(':')[-1].strip()
        self.Thread_count = os_command(GET_THREAD_COUNT).split('\n')[0].split(':')[-1].strip()
        self.Max_speed = os_command(GET_MAX_SPEED).split('\n')[0].split(':')[-1].strip()
        self.NUMA_node =  os_command(GET_NUMA_NODE_COUNT).strip().split('\n')[0].split(':')[-1].strip()
        


    def log_to_console_processor_details(self):
        print("Processor : {}, Socket#{}, Core#{} ,Thread#{}, MaxSpeed#{}, NUMA_NODE(S)#{} \n".format(self.processor_name,self.Socket_count,self.Core_count,self.Thread_count,self.Max_speed,self.NUMA_node))


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


    def log_to_console_memory_details(self):    
        print("Memory : Total Memory#{}, PerDIMM#{} {} {}, Populated DIMM's#{}\n".format(self.Total_memory,self.Dimm_size,self.Dimm_type,self.Dimm_speed,self.No_of_active_dimms))

    
    def log_to_console_mlnx_device_details(self):
        print("Mellanox Devices :")
        for bus_id in Bus_id_list:
            print("{} {} FW#{} PCISlot#{} NUMAnode#{} Lw#{} Ls#{} P/N#{} PSID#{} {} {} {}".format(bus_id.name,bus_id.Chipset,bus_id.FW_version,bus_id.Physical_slot,bus_id.NUMA_node,bus_id.Link_width,bus_id.Link_speed,bus_id.Part_number,bus_id.PSID,bus_id.Interface_name,bus_id.Network_if_name,bus_id.Product_name))


class hpe_bios:


    def get_os_settings(self):
        global Bus_id_list
    
        self.Firewall_status = os_command(GET_FIREWALL_STATUS).strip().split(':')[-1]
        self.IRQ_balance = os_command(GET_IRQBALANCE_STATUS).strip().split(':')[-1]
        self.Ipv4_tcp_timestamps = os_command(GET_IPV4_TCP_TIMESTAMPS).strip()
        self.Ipv4_tcp_sack = os_command(GET_IPV4_TCP_SACK).strip()
        self.Netdv_max_backlog = os_command(GET_CORE_NETDV_MAX_BACKLOG).strip()
        self.Core_rmem_max = os_command(GET_NET_CORE_RMEM_MAX).strip()
        self.Core_wmem_max = os_command(GET_NET_CORE_WMEM_MAX).strip()
        self.Core_rmem_default = os_command(GET_NET_CORE_RMEM_DEFAULT).strip()
        self.Core_wmem_drefault = os_command(GET_NET_CORE_WMEM_DEFAULT).strip()
        self.Core_optmem_max = os_command(GET_NET_CORE_OPTMEM_MAX).strip()
        self.Net_ipv4_tcp_rmem = os_command(GET_NET_IPV4_TCP_RMEM).strip().split()[-1]
        self.Net_ipv4_tcp_wmem = os_command(GET_NET_IPV4_TCP_WMEM).strip().split()[-1]
        self.Net_ipv4_tcp_low_latency = os_command(GET_NET_IPV4_TCP_LOW_LATENCY).strip()
        
        for bus_id in Bus_id_list:
            if bus_id.Network_if_name != "":
                bus_id.LRO_ON = os_command(GET_LRO_ON.format(bus_id.Network_if_name)).strip().split(':')[-1]
                bus_id.Rx_gro_hw = os_command(GET_RX_GRO_HW.format(bus_id.Network_if_name)).strip().split(':')[-1]
                bus_id.Rx_usecs = os_command(GET_RX_USECS.format(bus_id.Network_if_name)).strip().split(':')[-1]
                bus_id.Tx_usecs = os_command(GET_TX_USECS.format(bus_id.Network_if_name)).strip().split(':')[-1]
            

    def log_to_console_os_settings(self):
        print(self.Firewall_status,self.IRQ_balance)
        print(self.Ipv4_tcp_timestamps,self.Ipv4_tcp_timestamps,self.Netdv_max_backlog,self.Core_rmem_max,self.Core_wmem_max,self.Core_rmem_default,self.Core_wmem_drefault,self.Core_optmem_max,self.Net_ipv4_tcp_rmem,self.Net_ipv4_tcp_wmem,self.Net_ipv4_tcp_low_latency)
        for bus_id in  Bus_id_list:
            print(bus_id.LRO_ON,bus_id.Rx_gro_hw,bus_id.Rx_usecs,bus_id.Tx_usecs)


if __name__=='__main__':

    
    if len(sys.argv)==2:
        
        get_Bus_id_list()

        get_mlnx_device_details()
        
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
            
            report = report()
            
            report.get_os_details()
            
            report.log_to_console_os_details()
            
            report.get_bios_details()
            
            report.log_to_console_bios_details()

            report.get_processor_details()
            
            report.log_to_console_processor_details()
            
            report.get_memory_details()
                     
            report.log_to_console_memory_details()

            report.log_to_console_mlnx_device_details()


        elif sys.argv[1]=='--hpe_bios' or sys.argv[1]=='-b':

            hpe_bios = hpe_bios()

            hpe_bios.get_os_settings()
            
            hpe_bios.log_to_console_os_settings()

            



   