import paramiko
from tkinter import messagebox
from tkinter import *
import os
import subprocess
import time
import sys

def ssh_command(command):
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


file = open('log.txt','w')
file.close()



if sys.argv[1]=='--help' or sys.argv[1]=='-h':
    print("Help")

elif sys.argv[1]=='-report' or sys.argv[1]=='-r':
    Os_name = ssh_command("cat /etc/os-release | grep 'PRETTY_NAME'").strip().split('=')[-1]
    Os_kernel_version = ssh_command("uname -r").strip()
    print("\nOS : {} Kernel version is {} \n".format(Os_name,Os_kernel_version))

    Bios_release_date = ssh_command("dmidecode -t bios | grep 'Release Date:'").strip().split(':')[-1]
    Bios_version =  ssh_command("dmidecode -t bios | grep 'Version:'").strip().split(':')[-1]
    print("Bios : {} {} \n".format(Bios_version,Bios_release_date))

    processor_name = ssh_command("dmidecode -t processor | grep 'Version'").split('\n')[0].split(':')[-1]
    Socket_count = len(ssh_command("dmidecode -t processor | grep 'Version'").strip().split('\n'))
    Core_count = ssh_command("dmidecode -t processor | grep 'Core Count'").split('\n')[0].split(':')[-1].strip()
    Thread_count = ssh_command("dmidecode -t processor | grep 'Thread Count'").split('\n')[0].split(':')[-1].strip()
    Max_speed = ssh_command("dmidecode -t processor | grep 'Max Speed'").split('\n')[0].split(':')[-1].strip()
    NUMA_node =  ssh_command("lscpu | grep NUMA").strip().split('\n')[0].split(':')[-1].strip()

    print("Processor : {}, Socket#{}, Core#{} ,Thread#{}, MaxSpeed#{}, NUMA_NODE(S)#{} \n".format(processor_name,Socket_count,Core_count,Thread_count,Max_speed,NUMA_node))
   
    summ = 0
    for item in ssh_command("dmidecode -t memory | grep 'Number Of Devices:'").strip().split('\n'):
        summ += int(item.strip().split(':')[-1])
    No_of_dimms = summ
    summ = 0
    count = 0
    for item in ssh_command("dmidecode -t memory | grep '^\s*Size:'").strip().split('\n'):
        if 'No Module Installed' not in item:
            Dimm_size = item.strip().split(':')[-1].strip()
            count +=1
    Total_memory = ssh_command("free | grep Mem | awk '{print $2}'").strip()
    
    Total_memory, Dimm_size = conversion(Total_memory,Dimm_size)
    

    No_of_active_dimms = count
    for item in ssh_command("dmidecode -t memory | grep '^\s*Speed:'").strip().split('\n'):
        if 'Unknown' not in item:
            Dimm_speed = item.strip().split(':')[-1]
            break
    for item in ssh_command("dmidecode -t memory | grep '^\s*Type:'").strip().split('\n'):
        if 'Type Detail' not in item and 'Other' not in item:
            Dimm_type = item.strip().split(':')[-1]
            break
    print("Memory : Total Memory#{}, PerDIMM#{} {} {}, Populated DIMM's#{}\n".format(Total_memory,Dimm_size,Dimm_type,Dimm_speed,No_of_active_dimms))



    #lscpu_data = ssh_command("lscpu")
    #cpu_info = ssh_command("cat /proc/cpuinfo")
    #print(cpu_info)
    mellanox_devices = ssh_command("lspci | grep -i mell")
    #print("Mellanox Devices \n",mellanox_devices)
    mellanox_devices_list = mellanox_devices.strip().split('\n')
    #print(mellanox_devices_list)
    temp_list = [ item.split()[0] for item in mellanox_devices_list]
    bus_id_list = [temp_list[0]]
    for elem in range(1,len(temp_list)):
        if temp_list[elem][:2]!=temp_list[elem-1][:2]:
            bus_id_list.append(temp_list[elem])
    #print(temp_list)
    #print(bus_id_list)
    print("Mellanox Devices :")
    for bus_id in bus_id_list:
        Physical_slot = ssh_command("lspci -vvvs "+bus_id+" | grep -i 'Physical slot:' | awk '{print $3}'").strip()
        if Physical_slot == '':
            Physical_slot = 'None'
        NUMA_node = ssh_command("lspci -vvvs "+bus_id+" | grep -i 'NUMA node:' | awk '{print $3}'").strip()
        Part_number = ssh_command("lspci -vvvs "+bus_id+" | grep -i 'Part number:' | awk '{print $4}'").strip()
        Product_name = ssh_command("lspci -vvvs "+bus_id+" | grep -i 'Product name:'").strip().split(':')[-1]
        Link_speed = ssh_command("lspci -vvvs "+bus_id+" | grep -i 'LnkSta:' | awk '{print $3}'").strip()
        Link_width = ssh_command("lspci -vvvs "+bus_id+" | grep -i 'LnkSta:' | awk '{print $5}'").strip()
        NUMA_node = ssh_command("lspci -vvvs "+bus_id+" | grep 'NUMA node:' | awk '{print $3}'").strip()
        Chipset = ssh_command("lspci -vvvs "+bus_id+" | grep '"+bus_id+"'").strip().split()[-1]
        if 'Connect' not in Chipset:
            temp = ssh_command("lspci -vvvs "+bus_id+" | grep '"+bus_id+"'").strip().split()
            Chipset = temp[-2]+" "+temp[-1]
        interface_name = ssh_command("ls -l /sys/class/infiniband/* | grep "+bus_id).strip().split('/')[-1]
        #print(interface_name)
        FW_version = ssh_command("ibstat  "+interface_name+" | grep 'Firmware version:' | awk '{print $3}'").strip()
        if interface_name=='':
            interface_name = 'None'
        network_if_name = ssh_command("ls -l /sys/class/net/* | grep '"+bus_id+"'").strip().split('/')[-1]
        if network_if_name=='':
            network_if_name = 'None'
        PSID = ssh_command("~/HpeFabricsTuner/mstflint -d "+bus_id+" q | grep PSID: | awk '{print $2}'").strip()
        
        print("{} {} FW#{} PCISlot#{} NUMAnode#{} Lw#{} Ls#{} P/N#{} PSID#{} {} {} {}".format(bus_id,Chipset,FW_version,Physical_slot,NUMA_node,Link_width,Link_speed,Part_number,PSID,interface_name,network_if_name,Product_name))

    """with open("log.txt","a") as file:
        #file.write('command = "lspcu"\n')
        #file.write(lscpu_data+"\n\n")
        file.write('command = "cat /proc/cpuinfo"\n')
        file.write(cpu_info+"\n\n")
        file.write('command = "lspci | grep -i mell"\n')
        file.write(mellanox_devices+"\n\n")"""

#result = subprocess.run("dir",shell=True,capture_output=True)
#print(result.stdout.decode())
    
   