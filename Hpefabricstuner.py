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

file = open('log.txt','w')
file.close()



if sys.argv[1]=='--help' or sys.argv[1]=='-h':
    print("Help")

elif sys.argv[1]=='-report' or sys.argv[1]=='-r':
    result = ssh_command("lscpu | grep 'Model name'").split()
    processor_name = ' '.join(result[2:])
    #print(processor_name)
    lscpu_data = ssh_command("lscpu")
    cpu_info = ssh_command("cat /proc/cpuinfo")
    #print(cpu_info)
    mellanox_devices = ssh_command("lspci | grep -i mell")
    mellanox_devices_list = mellanox_devices.strip().split('\n')
    #print(mellanox_devices_list)
    temp_list = [ item.split()[0] for item in mellanox_devices_list]
    bus_id_list = [temp_list[0]]
    for elem in range(1,len(temp_list)):
        if temp_list[elem][:2]!=temp_list[elem-1][:2]:
            bus_id_list.append(temp_list[elem])
    #print(temp_list)
    #print(bus_id_list)
    with open("log.txt","a") as file:
        file.write('command = "lspcu"\n')
        file.write(lscpu_data+"\n\n")
        file.write('command = "cat /proc/cpuinfo"\n')
        file.write(cpu_info+"\n\n")
        file.write('command = "lspci | grep -i mell"\n')
        file.write(mellanox_devices+"\n\n")

#result = subprocess.run("dir",shell=True,capture_output=True)
#print(result.stdout.decode())
    
   