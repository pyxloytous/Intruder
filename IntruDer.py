#!/usr/bin/python3

import concurrent.futures
#import itertools
import time, datetime
from colorama import Fore, Style, init as colorama_init
#import socket
import subprocess
from pathlib import Path
import sys
import argparse
#import figlet
#import logging
#from itertools import islice
import scapy.all as scapy
#from tqdm import tqdm # tqdm.tqdm





tcp_port_string = ''
udp_port_string = ''
output_path = ''
udp_open_filtered_port_string = ''
tcp_open_filtered_port_string = ''
port_list_generated_from_passed_file = []
udp_ports_to_be_rescanned = []  # The ports which scapy UDP scan reneders None as a result are added here for another try to confirm - If No ICMP response it means port is reachable and Open - so its good to give a retry and confirm 
command_list = []
closed_confirmed_port_list = []





#Color Defination
colorama_init(autoreset=True)
#S_RST = Style.RESET_ALL

CLG = Fore.LIGHTGREEN_EX
CLY = Fore.LIGHTYELLOW_EX
CLB = Fore.LIGHTBLUE_EX
CLW = Fore.LIGHTWHITE_EX
CLR = Fore.LIGHTRED_EX
CLC = Fore.LIGHTCYAN_EX
CLM = Fore.LIGHTMAGENTA_EX
CB = Fore.BLUE
CC = Fore.CYAN
CY = Fore.YELLOW
CR = Fore.RED
CG = Fore.GREEN
CW = Fore.WHITE
CM = Fore.MAGENTA


sorry = f'''{CLR}
          ____                                  
         / ___|    ___    _ __   _ __   _   _   
         \___ \   / _ \  | '__| | '__| | | | |  
          ___) | | (_) | | |    | |    | |_| |  
         |____/   \___/  |_|    |_|     \__, |  
                                	|___/  
        '''


banner = f'''{CLM}

      {CLW}_____________________________________________________________________________________________________
     //----------------------------------------------------------------------------------------------------\\\\
     ||                                                                                                    || 
     ||   {CLR}8888888 888b    888 88888888888 8888888b.  888     888 8888888b.  8888888888 8888888b            ||
     ||     888   8888b   888     888     888   Y88b 888     888 888  "Y88b 888        888   Y88b          ||
     ||     888   88888b  888     888     888    888 888     888 888    888 888        888    888          ||
     ||     888   888Y88b 888     888     888   d88P 888     888 888    888 8888888    888   d88P          ||
     ||     888   888 Y88b888     888     8888888P"  888     888 888    888 888        8888888P            ||         
     ||     888   888  Y88888     888     888 T88b   888     888 888    888 888        888 T88b            ||
     ||     888   888   Y8888     888     888  T88b  Y88b. .d88P 888  .d88P 888        888  T88b           || 
     ||   8888888 888    Y888     888     888   T88b  "Y88888P"  8888888P"  8888888888 888   T88b          ||
     ||                                                                                                    ||
     ||                             {CLY} +-+-+-+-+-+-+-+-+-+-+-+-+-+                                           ||
     ||                              |T|H|E| |A|U|T|O|M|A|T|E|R|                                           ||
     ||                              +-+-+-+-+-+-+-+-+-+-+-+-+-+                                           ||
     ||                                                                                                    ||
     ||                                     {CLB} +-+-+-+-+                                                     ||
     ||                                      |f|r|o|m|                                                     ||
     ||                                      +-+-+-+-+                                                     ||
     ||                                                                                                    ||
     ||                      {CLC}+-+-+-+-+-+-+-+--+-+--+-+-+-+-+-+-+-+-+-+-+-+                                 ||
     ||                      |p|y|x|l|o|y|t|o|u|s| |@| |g|m|a|i|l|.|c|o|m|                                 ||
     ||                      +-+-+-+-+-+-+-+-+-+-+--+--+-+-+-+-+-+-+-+-+-+                                 ||
     {CW}\\\\____________________________________________________________________________________________________//
      -----------------------------------------------------------------------------------------------------



        '''







def helping_hand():

    print (f'''{CLC}
    usage: {sys.argv[0]} [-h] -IP IP [-P] [-R] [-F] [-T S] [-N] [-O] [-T]

    optional arguments:
    -h        -- help  show this help message and exit
    -IP       -- Takes ip-address | 192.168.2.1
    -p        -- Takes a single PORT to scan (if port range is not given)
    -R        -- Takes ua PORT-RANGE to scan (if single port is not given)
    -F        -- Takes FILE-PATH for PORTS to scan | /root/Desktop/some_file.txt
    -S        -- Takes PORTS in SEQUENCE to scan | 20,21,23,80,443,445
    -N        -- Takes number of threads to be created during scan | Default 100 | 100 is best for UDP scan for acuracy
    -O        -- Takes scripts OUT-PUT PATH to save detialed nmap scan | /root/Deskopt/SomneFolder
    -T        -- Takes PROTOCOL-TYPE to scan | TCP/UDP
    -M        -- Takes SCAN-METHOD| Python/Nmap
    -V        -- Shows what commands this script generate to call them further in separate terminal and tab inctences

    {CLY}Example   {CLB}:  {CY}python3 IntruDer_v01.py -IP 192.168.116.131 -R 1-65535 -N 100 -T TCP -O /root/Desktop/test -M python

        ''')



    


def argumentParser():

    parser = argparse.ArgumentParser()
    parser.add_argument('-IP', action='store', default=False, dest='IP', required=False, help='Takes ip-address | 192.168.2.1') #req tru
    parser.add_argument('-R', action='store', default=False,  help='Takes a single PORT to scan')
    parser.add_argument('-P', action='store', default=False,  help='Takes ua PORT-RANGE to scan')
    parser.add_argument('-F', action='store', default=False,  help='Takes FILE-PATH for PORTS to scan | /root/Desktop/some_file.txt')
    parser.add_argument('-S', action='store', default=False,  help='Takes PORTS in SEQUENCE to scan | 20,21,23,80,443,445')
    parser.add_argument('-N', action='store', default=100,   help='Takes number of threads to be created during scan | Default 100 | 100 is best for UDP scan for acuracy')
    parser.add_argument('-O', action='store', default=False, required=False, help='Takes scrips OUT-PUT PATH to save detialed nmap scan | /root/Deskopt/SomneFolder')
    parser.add_argument('-T', action='store', default=False, required=False, help='Takes PROTOCOL-TYPE to scan | TCP/UDP')
    parser.add_argument('-M', action='store', default=False, required=False, dest='M', help='Takes SCAN-METHOD| Python/Nmap')
    parser.add_argument('-V', action='store_true', required=False, help='Shows what commands this script generate to call them further in separate terminal and tab inctences.')


    args = parser.parse_args()

    if (not args.IP or args.IP == False):
       helping_hand()
       print (f'   {CR} [-] {CLR}IP-Address (-IP) is required. Exiting program....\n')
       sys.exit(0)
    else:
        print (f'{CLY} [+] IP-Address: {CLG} {args.IP}')
    if not args.R and not args.P and not args.F and not args.S:
       helping_hand()
       print (f'{CLR} [-] Either PORT (-P) or a PORT-RANGE (-R) or FILE (-F) for default UDP ports or Port-Sequence (-S) is required. Exiting program....')
       sys.exit(1)
    else:
        if args.P:
            print (f'{CLY} [+] PORT: {CLG} {args.P}')
        if args.R:
            print (f'{CLY} [+] PORT-RANGE: {CLG} {args.R}')
            if '-' not in args.R:
                helping_hand()
                print (f'{CLR} [+] PORT-RANGE (-R) is required in {CLB} 10-500 {CLR} format. Exiting program....')
                sys.exit(2)
        if args.F:
            print (f'{CLY} [+] FILE-PATH (Defaul UDP Ports): {CLG} {args.F}')
        if args.S:
            print (f'{CLY} [+] POET-SEQUENCE: {CLG} {args.S}')

    if (int(args.N) != 100):
        print (f'{CLR} [-] [Warning] THREADS parameter (-N) set OTHER Value than DEFAULT VALUE [100]: {CLG} {args.N}')   
        print (f'{CR} [-] [Wassrning] For better result please set THREADS parameter (-N): {CLG} 100')      
       #helping_hand()
    else:
        print (f'{CLY} [+] THREADS (-N) set to DEFAULT: {CLG} {args.N}')


    if (args.T is False):
       helping_hand()
       print (f'{CLR} [-] PROTOCOL (-T) is required to be defined to slect the port scan type TCP/UDP. Exiting program....')
       sys.exit(3)
    else:
        print (f'{CLY} [+] PROTOCOL-TYPE: {CLG} {args.T}')


    if ((args.M == 'nmap') or (args.M == 'NMAP')) or ((args.M == 'python') or (args.M == 'PYTHON')):
        print (f'{CLY} [+] SCANNER-TYPE: {CLG} {args.M}')
    else:
       helping_hand()
       print (f'{CLR}  [-] A correct (SCANNER-TYPE) {CW}\'-M\' {CLR}is required.  {CLW}PYTHON/NMAP. {CLR}Exiting program....')
       sys.exit(4)




    if (args.O is False):
       helping_hand()
       print (f'{CLR} [-] OUT-PUT (-O) is required to be defined to save Nmap result. Exiting program....')
       sys.exit(5)
    else:
        print (f'{CLY} [+] OUT-PUT path for Nmap Result: {CLG} {args.O}')

    print()

    print()

        
    return args



def check_if_object_is_list(object):
    list_status = isinstance(object, list)
    return list_status




def time_duration_caculator(time_type, **kwargs):
    '''Takes first argument as start_time. Second argument as end_time. Third argument as previously set start_time when calculating timeduration.

    usage: 
        start_time = time_duration_caculator(start, action='UDP_PORT_SCAN', previous_start_time=None)
        time_duration_caculator(end, previous_start_time=start_time)'''

    time_type = time_type
    for k, v in kwargs.items():            
        if 'action' in k:
            action = kwargs[k]
        if 'previous_start_time'  in k:
            previous_start_time = (kwargs[k])
    if time_type == 'end':
        end_time = datetime.datetime.now().replace(microsecond=0)
        time_duration = end_time - previous_start_time
        print(f'\n{CLC}    {CY}Time-Stats for [{action}]:')
        print (f'    {CLB}Start time       : {CY}{previous_start_time}')
        print (f'    {CLB}End time         : {CY}{end_time}')
        print (f'    {CLR}Total Time Taken : {CY}{time_duration}\n\n')
        del previous_start_time #Deletes previous set time to release it from memory and to be set freshly in next call of time function.
    elif time_type == 'start':
        start_time = datetime.datetime.now().replace(microsecond=0)
        return start_time




        
def Multi_Bash_Command_Executer(final_command_list):
    commands = final_command_list

    terminal = ['gnome-terminal']

    for cmd in (commands):
        if cmd != '':
            terminal.extend(['--tab', '-e', f'''bash -c 'echo "{cmd}"; echo; {cmd}; exec /bin/bash -i' '''])
            
 
    try:
        print (f'{CLG}[*] {CLC}Calling the Ginnie to do the magic and automatically calling several functions one by another.\n')
        res = subprocess.call(terminal, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print (f'          {CY} And here the {CLC}Ginnie {CY}appeared :)\n')
    except Exception as e:
        print (f'\n{CLR}[-]  {CLB}Something went wrong in execution of below command{CLR} (:\n')
        print (f'{CLR}[-] {CLR} {cmd} \n')
        print (f'{CLR}[-] ERROR: {CLC}{e}\n')
  

  


def Bash_Command_Executer(cmd):

    try:
        res = subprocess.run(cmd, shell=True, capture_output=True)

        if  res.returncode == 0:
            return res

    except subprocess.CalledProcessError as e:
        print (f'\n{CLR}[-]  {CLB}Something went wrong in execution of below command{CLR} (:\n')
        print (f'{CR}[-] {CLR} {cmd} \n')
        print (f'{CLR}[-] ERROR: {CLC}{e}\n')
        pass

   

def file_checker(path_objects):

    not_found = []
    found = []

    path = path_objects
    if isinstance(path_objects, list):
        for path in path_objects:
            path = Path(path)
            if path.is_file():
                found.append(path)
            else:
                not_found.append(path)
                
    else:
        path = Path(path_objects)
        if path.is_file():
            found.append(path)
        else:
            not_found.append(path)
            #print(f'\n{CLR}[-] {CLY} FILE [{CLB}{path}] {CLY} is missing- check their availability!\n')
          

    if found:
        print(f'{CLG}\n[+] {CLY} Below word-list files is/are present - Good to go :) \n')
        for f in found:
            print(f'	"{CLC}{f}"\n')
        #return found

    if not_found:
        print(f'{CR}[-] Missing files from their path - {CLR}Ensure their availaity and set path in {CLM}"#File-Dir Paths used in the script" {CLR} section under main() function of the {CLY}<{sys.argv[0]}> !\n')
        for f in not_found:
            print(f'	"{CY}{f}"\n')

        print(f'{CY}[Q] {CLB} Do you still want to CONTINUE {CLC}or {CLB} EXIT and set the require file path in the {CLY}<{sys.argv[0]}>\n')
        print(f'{CY}[I] {CLB} If CONTINUE, Most of the bruteforcing scripts would not work \n')

        while 1:
            inp = input(f'{CLC}YES/NO >>')
            if inp.lower() == 'yes' or inp.lower() == 'y':
                break
            elif inp.lower() == 'no' or inp.lower() == 'n':
                 print(f'{CLB}[-] {CLR} OK - Exiting ...\n')
                 sys.exit(0)
                 break
            else:
                 print(f'{CLB}[-] {CLR} Wrong answer. Please try again! \n')
    return







def dir_creator(path_objects):

    not_found = []
    found = []
    newly_made_folders = []
    path = path_objects
    if isinstance(path, list):
        for path in path_objects:
            path = Path(path_objects)
            if path.is_dir():
                found.append(path)
            else:
                not_found.append(path)
                print(f'{CLR}[-] {CLY} FOLDER [{CLB}{path}] {CLY} is missing- check their availability!\n')
    else:
        path = Path(path_objects)
        if path.is_dir():
            found.append(path)
        else:
            not_found.append(path)
            print(f'{CLR}[-] {CLY} FOLDER [{CLB}{path}] {CLY} is missing- check their availability!\n')
        
            

    if found:
        print(f'{CLG}[+] {CLY} Below FOLDER to save output of verious scripts present - Good to go :) \n')
        for d in found:
            print(f'{CLG}	 {CLC}{d}  \n')
            return d
    if not_found:
        print(f'{CY}[?] {CLB} Do you still want to CONTINUE ? \n')
        inp = input(f'{CLC}YES/NO >>')

        while 1:
            if inp.lower() == 'yes' or inp.lower() == 'y':
                break
            elif inp.lower() == 'no' or inp.lower() == 'n':
                print(f'{CLB}[-] {CLR} OK - Exiting ...\n')
                sys.exit(1)
                break
            else:
                print(f'{CLB}[-] {CLR} Wrong answer. Please try again! \n')

        for missing in not_found:
            path = Path(missing)
            path.mkdir(parents=True)
            newly_made_folders.append(path)

    if newly_made_folders:
        print(f'{CLG}[+] {CLY} Missing FOLDER(s) Created - Now good to go :) \n')
        for d in newly_made_folders:
            print(f'{CLG}[+]	 {CLC}"{d}"  \n')
            return d



def scan_with_nmap(ip, ports, verbosity, protocol_type):

    port_sequence = ''
    ports = ports
    ip = ip
    nmap_cmd = ''
    global tcp_port_string
    global udp_port_string


    if protocol_type == 'TCP':
        nmap_cmd = f'nmap  {ip} -Pn -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p{ports} -oN {output_path}/{ip}_TCP_light_nmap_result'
        print(f'{CLG}[*] {CLC}Starting TCP-light port scan on {CLY}{ip}: {ports}\n')
        print(f'           {CY} COMMAND: {CW} {nmap_cmd} \n') 

        res = Bash_Command_Executer(nmap_cmd)
        if verbosity:
            res = res.stdout.decode("utf-8").split('\n')
            for i in res:
                print(f'{CLC}           {i}')

        cmd  = f'cat {output_path}/{ip}_TCP_light_nmap_result | grep open | cut -d "/" -f 1'
        res = Bash_Command_Executer(cmd)
        res = res.stdout.decode("utf-8").split('\n')
        for p in res:
            if p != '':
                tcp_port_string += p + ','

    elif protocol_type == 'UDP':
        nmap_cmd = f'nmap {ip} -Pn -sU --stats-every 3m --max-retries 3 --max-scan-delay 20 -T4 -p{ports} -oN {output_path}/{ip}_UDP_light_nmap_result'
        print(f'{CLG}[*] {CLC}Starting UDP-light port scan on {CLY}{ip}: {ports}\n')
        print(f'           {CY} COMMAND: {CW} {nmap_cmd} \n') 

        res = Bash_Command_Executer(nmap_cmd)
        if verbosity:
            res = res.stdout.decode("utf-8").split('\n')
            for i in res:
                print(f'{CLC}           {i}')

        cmd = f'cat {output_path}/{ip}_UDP_light_nmap_result | grep open | cut -d "/" -f 1'
        res = Bash_Command_Executer(cmd)
        res = res.stdout.decode("utf-8").split('\n')

        for p in res:
            if p != '':
                port_sequence += p + ','
                udp_port_string.strip(',')





def Banner_Grabber(port, service, ip, protocol_type):
    ''' It gives option to chose if first port scan has to be done with python or nmap.
        It will create a port string that will be again passed to python for service scan.
    '''    

    port = port
    service = service #service grabbed from service_dict
    ip = ip


    #banner_cmd = f'python3 -c 'import socket;sockettimeout(0.30); s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.connect(({ip}, {port}));banner = s.recv(1024); banner = banner.strip()'
    #banner_cmd = f'''python3 -c "import socket; socket.setdefaulttimeout(5);s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.connect(('{ip}', {port})); banner = s.recv(1024); banner = banner.strip(); print(banner)" '''
    banner_cmd = ''

    if protocol_type == 'TCP':
        banner_cmd = f'nc -v {ip} -z -w1 {port}'
    elif protocol_type == 'UDP':
        banner_cmd = f'nc -v {ip} -z -w1 {port}'

    print(f'{CY}COMMAND: {CLB}{banner_cmd} \n')
    res = Bash_Command_Executer(banner_cmd)
    #print (res)
    if res is not None:
        for i in (res.stderr.decode().split('\n')):
            if 'UNKNOWN' in i:
                print(f'{CB}[+] Banner found on  {CLY} --> {ip}: {port}')
                print(f'        {CLY}    BANNER:     {i}\n')
    else:
        print(f'{CR}[+] {CLR}Sorry, Banner could not be retrieved for  {CLC} --> {CLY}{ip}: {port}  \n')

    return





def nfs(ip, port, service): 
  
    global output_path

    #print(f'{CLG}[+] {CLC}{service} {CY}service found on port {CLC}{ip}: {port}\n')
    print(f'{CLG}[*] {CG} Executing below command for further scan...\n')
    NFSENUM = f'nmap -p {port} --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -oN {output_path}/{ip}_nfs_nmap_enum_{port} {ip}'
    print(f'           {CY} COMMAND: {CC} {NFSENUM} \n') 
    command_list.append(NFSENUM)

    #Enumerating file shares manually
    print(f'{CLG}[*] {CLC}{service} {CLY}Enumerating NFS details manually also....')

    

    try:
        line = f'{CLM}='
        nfs_cmd_1 = f'showmount -e {ip}'
        res_nfs_1 = Bash_Command_Executer(nfs_cmd_1)
        shared_file_folder = []
        if res_nfs_1 is not None or res_nfs_1 != 1:
            res_list = res_nfs_1.stdout.decode().split('\n')
            for i in res_list:
                if '*' in i:
                    if i not in shared_file_folder:
                        shared_file_folder.append(i)
                    

        ip_sharing_file_folder = ''
        for i in res_list:
            if 'Export' in i:
                if i not in ip_sharing_file_folder:
                    ip_sharing_file_folder += i
                    ip_sharing_file_folder.split()[-1].strip(':')


        for mounts in shared_file_folder:
            mounts = mounts.split()[0]
            #print (mounts)  
            #Defining local tmp dir in attacking machine where the share would be mounted
            temp_dir = f'{output_path}/local_mountpoint_{ip}_{mounts}_{port}'     
            print(f'    {CG} Creating mount point [{temp_dir}] and {CLY}mouting target share [{CC}{mounts}]...\n')

            #Checking if temp_dir already exist, else will create it
            temp_dir = dir_creator(temp_dir)

            mount_cmd = f'mount -o nolock -t nfs {ip}:{mounts} {temp_dir}'
            ls_cmd = f'ls -lha {temp_dir}'


            if shared_file_folder:
                file_folder_list = []
                res_nfs2 = Bash_Command_Executer(mount_cmd)
                if res_nfs2 is not None:
                    print(f'        {CLC}Mount_point/s created for {mounts} is {CLC} --> {CLC} {temp_dir}')
                    print
                    res_nfs3 = Bash_Command_Executer(ls_cmd)
                    if res_nfs3 is not None and res_nfs3.returncode == 0:
                        temp_share_list = res_nfs3.stdout.decode()
                        print (    f'{line}' * 60)
                        print(f'        {CLC} List of FILE/FOLDERS in mounted FOLDER as: {CLY}{mounts}')
                        print(f'            {CLY}str({temp_share_list})')        
                        print (    f'{line}' * 60)                
                    else:
                        print(f'{CLG}[-] Target share {CLY}[{mounts}] could not be mounted. Please check manually with below command')
                        print

    except Exception as e:
        print (f'{CLB}[-] {CLR}Share File cannot be mounted/parsed due to this Error:')
        print (f'    {CR}ERROR: {CLR}{e}')





def smb_share_and_file_list(ip, port):

    #importing and version checking
    from impacket import smbconnection, version
    impacket_banner = version.BANNER
    version =  impacket_banner.split()[1]
    #sub_version = int(version.split()[1].split('.')[-1].split('-')[0])
    sub_version = (version.split('.')[-1].split('-')[0])

    print(f'{CLC}[*] {CLY} Checking impacket version before exeuting SMB component of \'smb_share_and_file_list\' script.... \n')
    print(f'{CLG}[+] {CLY} Impacket version: {version} \n')



    if int(sub_version) < 16: # less than v0.9.16-dev
        print(f'{CLR}[-] Warning! Impacket version is lover than {CY}\'v0.9.16-dev\' \n')
        print(f'{CLR}[-] SMB component of this script may NOT run properly and you may lose some importnat info ! \n')

    try:
        s = smbconnection.SMBConnection('\\*SMBservice', ip, sess_port=port)
        if s.login(' ', ' '): #- null session
            print(f'{CLG}[+] {CLY} Null session with user_name "\'\'" and pass "\'\'" established. \n')
            print(f"{CLG}[+] {CY} Hurraaaaaah - {CLY}Many file operation can also be done now liek {CLC}[openFile', 'putFile', 'queryInfo', 'readFile', 'readNamedPipe','writeFile', 'writeNamedPipe']\n")
            print(f'{CLC}[*] {CLY} Checking service\'s basic info.... \n')
            print(f'{CLG}[+] {CLY} Remote serviceer Name: {CLC}{s.getServerName()} \n')
            print(f'{CLG}[+] {CLY} Remote serviceer OS:   {CLC}{s.getServerOS()} \n')
            print(f'{CLG}[+] {CLY} Remote serviceer IP:   {CLC}{s.getRemoteHost()} \n')

            share_list = []
            shares = s.listShares()
            for i in range(len(shares)):
                share_list.append(shares[i]['shi1_netname'].strip('\x00'))

            if share_list and len(share_list) !=0:
                print(f'{CLG}[+] {CLY} Following shares found on target:{ip} \n')
                for share in share_list:
                    print(f'{CLG}[+] {CLC} {share} \n')
            
            for share in share_list:
                try:
                    share = '\\\\' + share
                    files = s.listPath(share, '"\"')
                    print(f'{CLG}[+] {CLY} Share [{share}] is loaded to check available files and directories inside ! \n')
                    print(f'{CLG}[+] {CLY} These are the  file, directories of the loaded share. \n')
                    for f in files:
                        if f.is_directory() == 16: #is_directory function returns '16' - object is directory
                            if f.is_readonly() == 1:
                                print(f'{CLG}[+] {CY}Dir name: {CLB}{f.get_longname()}      -  {CY}Dir size: {CLB}{f.get_filesize(),}   -    {CLC}READ_ONLY S_RST')
                            else:    
                                print(f'{CLG}[+] {CY}Dir name: {CLB}{f.get_longname()}      -  {CY}Dir size: {CLB}{f.get_filesize(),}   -    {CLC}WRITABLE S_RST')
                    
                        if f.is_directory() == 0: #is_directory function returns 0 - object is file
                            if f.is_readonly() == 0:
                                print(f'{CLG}[+] {CY}Dir name: {CLB}{f.get_longname()}      -  {CY}Dir size: {CLB}{f.get_filesize(),}   -    {CLC}READ_ONLY S_RST') 
                            else:
                                print(f'{CLG}[+] {CY}Dir name: {CLB}{f.get_longname()}      -  {CY}Dir size: {CLB}{f.get_filesize(),}   -    {CLC}WRITABLE S_RST')
                except Exception as e:
                    print (f'\n{CLR}[-]  {CLB}Something went wrong in while getting file shares {share}{CLR} (:\n')
                    print (f'        {CLR}ERROR: {CR}{e}\n')
        
        print (f'\n{CLR}[-]  {CLB}SMB NULL SESSION NOT ALLOWED !{CLR} (:\n')               
    except Exception as e:
        print (f'\n{CLR}[-]  {CLB}Something went wrong with SMB null sesssion Connection !{CLR} (:\n')
        

    return






def port_from_file_parser(file_path, protocol_type):
    '''parsing default udp ports kept in a file and adding to a list for further processing'''
    #Default UDP ports fetched and collected to the file being parsed here are feom below websites
    #https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-ports.html  - (udp_common_ports_list_page_1)
    #cat udp_common_ports_list_page_1 | awk {'print $1'} | cut -d '/' -f 1 > udp_Port_list_1

    #http://www.networksorcery.com/enp/protocol/ip/ports00000.htm       - (udp_common_ports_list_page_2)
    #cat udp_common_ports_list_page_2 | awk {'print $1'}  | cut -d '' -f 1 > udp_port_list_2  

    '''
    Other that above any type TCP/UDP and any number of ports can be passed to the scanner through file argument from command file\
    to generate a port sequence and to be further passed to nmap port scanner for service scan and then for automating the calls of several scritps on them.
    '''
    global tcp_port_string
    global udp_port_string

    if protocol_type == 'TCP':
        with open(file_path, 'r') as f:
            for line in f.readlines():
                line = line.strip('\n')
                tcp_port_string += line + ','

    elif protocol_type == 'UDP':
        with open(file_path, 'r') as f:
            for line in f.readlines():
                line = line.strip('\n')
                udp_port_string += line + ','
        




def PortRangeParser(port_range):
    port_range = port_range
    #print (f'{CY}Port-Range:{CLC} [{port_range}]')
    if '-' in str(port_range):
        start_port = int(port_range.split('-')[0])
        end_port = int(port_range.split('-')[1])
        return start_port, end_port


def port_sequence_parser(port_sequence):
    port_list = []
    port_sequence = port_sequence
    temp_list = port_sequence.split(',')
    for i in temp_list:
        port_list.append(int(i))
    print (f'port_list created from port seq: {port_list}')
    return port_list



#Defining Number of threads by breaking entire port range into multiple port chunks (lists) that will be used by cocurrent.future module to creating threads and execute the same at a time to avoid raixe condition for CPU
def generate_multi_port_list(nThread, port_list=None, start=None, end=None): # It takes Either port list or start/end range to generate multiport_list like [[1,2],[3,4][5,6]
    number_of_ports = []
    multi_port_lists = []

    if (start is not None) and (end is not None):
        number_of_ports = range (start, end)
        number_of_ports = number_of_ports
    elif port_list is not None:
        number_of_ports = port_list
            
    for port in range(0, len(number_of_ports), nThread):
        chunked_list = list(number_of_ports[port:port + nThread]) # Loopong through Number of ports parsed through port_range option, with a distence of 100 and appending the value to a new list named chunked_list
        multi_port_lists.append(chunked_list)

    return multi_port_lists





def scan_port_with_python(ip, port, protocol_type, flag='S', retries=0):

    '''Creating IP packet based on TCP/UDP ports to sent to tatget and guess the port\
       status based on result. Funda behind guessing the open ports are.....
       In TCP protocol case, if tcp packet is recieved with flags (SYN, ACK) ports are supposed to be OPEN.
       In UDP case, since it does not work based on 3 way hand shake and is connection less protocol incomparision to TCP which is oriented protocol
       here comes the trick to wait for a while and check the ICMP codes in the returned packed. If it has ICMP layer and
       ICMP has type and code 3, it tells that the target port is unreachable MEANS not open.
       IF sent UDP packet does not return any thing but result looks to be "NONE", this shows the packet is open because a UDP cannont
       work like flags sharing/hand shaking.
      

    '''

    #global tcp_port_string
    global udp_port_string
    global closed_ports
    global udp_open_filtered
    icmp_codes = [2, 3, 6, 9, 10, 11, 12, 13]
    test_ports = []
    target_ip = ip
    protocol_type = protocol_type
    retries = retries
    random_source_port = scapy.RandShort() #scapy.RandShort()  - gives random number of ports
    target_port = port
    tcp_flag = flag  #{S:SYN, SA:SYN-ACKF, F:FYN, N:NULL, P:PUSH, X:XMAS}
    ip = scapy.IP(dst=target_ip) #Declaration of source IP is not necessary as scapy takes it automatically from defualt interface.   
    UDP_port = scapy.UDP(sport=random_source_port, dport=target_port)
    TCP_port = scapy.TCP(sport=random_source_port, dport=target_port, flags=tcp_flag)


    if protocol_type == 'TCP':        
        #payload = '\x00\x0a\x09\x0d'
        packet = (ip/TCP_port) #/payload)
        result = scapy.sr1(packet, verbose=0, timeout=1, retry=10)
        if result is None:
             msg = 'Filtered | No TCP Ack recieved |  firewall woudl be dropping the packets'
             res = result
             return target_port, msg, res


        elif result is not None:
            if result.haslayer(scapy.TCP):
                if str(result['TCP'].flags) == 'SA':
                    msg = 'Open | Confirmed'
                    res = result
                    #TCP_port = scapy.TCP(sport=random_source_port, dport=target_port, flags='RA')
                    #packet = (ip/TCP_port)
                    #result = scapy.sr1(packet, verbose=0, timeout=1, retry=0)
                    return target_port, msg, res
                else:
                    msg = 'Closed'
                    res = result
                    return target_port, msg, res


    if protocol_type == 'UDP':
        payload = '\x00\x0a\x09\x0d'
        packet = (ip/UDP_port/payload)
        result = scapy.sr1(packet, verbose=0, timeout=2, retry=45) #(for UDP best is timeout=2, retry=45  feasible for 100-200)
   
        if result is None:
            msg = 'OPEN | Retry it - Not even ICMP response'
            res = result
            return target_port, msg, res
        elif result.haslayer(scapy.UDP): #(If destination unreachabvle, it will rerun True due to ICMP  destination unreachable reply packet)
            msg = 'OPEN & CONFIRMED - UDP layer in returned packet received'
            res = result
            return target_port, msg, res
        elif result.haslayer(scapy.ICMP): #(If destination unreachabvle, it will rerun True due to ICMP  destination unreachable reply packet)
            if result.getlayer(scapy.ICMP).type == 3 and result.getlayer(scapy.ICMP).code == 3: #(type = 3 (dest-unreach), code = 3 (dest-unreachable))
                msg = 'Closed'
                res = result
                return target_port, msg, res
            elif result.getlayer(scapy.ICMP).type == 3 and result.getlayer(scapy.ICMP).code in icmp_codes: #(type = 3 (dest-unreach), code = 3 (dest-unreachable))
                msg = 'OPEN | filtered | May be behind Firewal'
                res = result
                return target_port, msg, res
        
            




def tcp_future_executor(arg_setter, port_list_or_port, nThread):
    #Creating Threads with concurrent.futures module for executing TCP port scan
    #Refference to global variables
    global tcp_port_string
    global tcp_open_filtered_port_string

    p_list = False
    single_port = False

    #Defining Number of Max-Workers  for future which will handle number of threads defined in terms of chunked port lists.
    list_status = check_if_object_is_list(port_list_or_port)
    if list_status:
        start_port_being_scanned = port_list_or_port[0]
        end_port_being_scanned = port_list_or_port[-1]
        print (f'{CM}[*] {CLY}PORT_CHUNKS {CM}being scanned: [{CLB}{start_port_being_scanned}{CY}-{CLB}{end_port_being_scanned}{CY}]\n')        
        if (len(port_list_or_port) != 1) and (len(port_list_or_port) <= nThread):
            workers = len(port_list_or_port)
            p_list = True
        else:
            workers = nThread
            p_list = True


    if not list_status:
        single_port = True
        workers = 1


    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor: #100 best with timeout=2 and retries=45 for UDP
        thread_list = []
        thread = ''

        if p_list:
            threads = [executor.submit(arg_setter, port) for port in port_list_or_port] #in range(start, end)] #iter(iterable_total_task)}
            thread_list = threads
        elif single_port:
            port = int(port_list_or_port)
            thread = executor.submit(arg_setter, port)



        if thread_list:
            for thread in concurrent.futures.as_completed(thread_list):
                if thread is not None or thread != 'None':

                    target_port, msg, res = thread.result()
                    if msg == 'Filtered | firewall woudl be dropping the packets':
                        tcp_open_filtered_port_string += str(target_port) + ','
                    elif msg == 'Open | Confirmed':
                       tcp_port_string += str(target_port) + ','

                    else:
                        pass

        elif thread and not None or thread != 'None':
            target_port, msg, res = thread.result()
            if msg == 'Filtered | firewall woudl be dropping the packets':
                tcp_open_filtered_port_string += str(target_port) + ','
            elif msg == 'Open | Confirmed':
                tcp_port_string += str(target_port) + ','

            else:
                pass






def udp_future_executor(arg_setter, port_list_or_port, nThread):
    #Creating Threads for executing UDP port scan

    global udp_port_string
    global udp_open_filtered_port_string
    global out_path

    p_list = False
    single_port = False

    #Defining Number of Max-Workers  for future which will handle number of threads defined in terms of chunked port lists.
    list_status = check_if_object_is_list(port_list_or_port)
    if list_status:
        start_port_being_scanned = port_list_or_port[0]
        end_port_being_scanned = port_list_or_port[-1]
        print (f'{CM}[*] {CLY}PORT_CHUNKS {CM}being scanned: [{CLB}{start_port_being_scanned}{CY}-{CLB}{end_port_being_scanned}{CY}]\n')        
        if (len(port_list_or_port) != 1) and (len(port_list_or_port) <= nThread):
            workers = len(port_list_or_port)
            p_list = True

    else:
        workers = nThread


    if not list_status:
        Single_port = True
        workers = 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor: #100 best with timeout=2 and retries=45 for UDP
        thread_list = []
        if p_list:
            threads = [executor.submit(arg_setter, port) for port in port_list_or_port] #in range(start, end)] #iter(iterable_total_task)}
            thread_list = threads
        if single_port:
            threads = executor.submit(arg_setter, port)
            thread_list = threads

        if thread_list:
            for thread in concurrent.futures.as_completed(threads):
                if thread is not None or thread != 'None':
                    target_port, msg, res = thread.result()
                    if msg == 'OPEN & CONFIRMED - UDP layer in returned packet received':
                        udp_port_string += str(target_port) + ','
                    elif msg == 'OPEN | Retry it - Not even ICMP response':
                        udp_ports_to_be_rescanned.append(target_port) # This will always return None and hence it proves port will be opened unlike the same in TCP. 
                    elif msg == 'OPEN | filtered | May be behind Firewal':
                        udp_open_filtered_port_string += str(target_port) + ','
                    elif msg == 'Closed':
                        pass






def scan_with_python_nmap(ip, verbosity, **kwargs):

    #Takes strings of TCP and UDP ports passed to it either by python_port_scanner function or list of list of ports or squence of ports through command line and to go for a detialed scan further.

    ip = ip
    verbosity = verbosity
    nmap_udp_args = f'-Pn -sU -sV -A --stats-every 3m --max-retries 3 --max-scan-delay 20 -T3  -oN {output_path}/{ip}_UDP_detailed_nmap_result'
    nmap_tcp_args = f'-Pn -sS -sV -A --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -oN {output_path}/{ip}_TCP_detailed_nmap_result'
    scan_tcp = False
    scan_udp = False


    for k, v in kwargs.items():
        if 'scan_tcp' in k:
            scan_tcp = True
        if 'scan_udp' in k:
            scan_udp = True
        if tcp_port_string in k:
            tcp_port_String = kwargs[k] #80
        if udp_port_string in k:
            udp_port_String = kwargs[k]


    if scan_tcp:
        start_time = time_duration_caculator('start')
        try:
            import nmap
        except nmap.PortScanneError as e:
        #except Exception as e:
            print(e)

        nm = nmap.PortScanner()

        print(f'{CLG}[*] {CLC}Starting TCP-Version-Scan on {CLY}{ip}: {tcp_port_string}\n')
 
        if verbosity:
                print(f'           {CY} COMMAND: {CC} nmap {nmap_tcp_args} \n') 

        scan_res = nm.scan(ip, tcp_port_string, arguments = nmap_tcp_args)

        time_duration_caculator('end', previous_start_time=start_time, action='Nmap_TCP_Scan')
        if scan_res:
            #Calling nmap_result_parser to parse scan_result and return service:ports dictinary
            tcp_port_service_dict = nmap_result_parser(ip, scan_res, parse_tcp=True)
            command_list = scan_the_services(ip, verbosity, tcp_port_service_dict=tcp_port_service_dict)
                

    if scan_udp:
        start_time = time_duration_caculator('start')
        try:
            import nmap
        except nmap.PortScanneError as e:
        #except Exception as e:
            print(e)

        nm = nmap.PortScanner()

        print(f'{CLG}[*] {CLC}Starting UDP-Version scan on {CLY}{ip}: {udp_port_string}\n')
 
        if verbosity:
                print(f'           {CY} COMMAND: {CC} nmap {nmap_udp_args} \n') 

        scan_res = nm.scan(ip, udp_port_string, arguments = nmap_udp_args)
        time_duration_caculator('end', previous_start_time=start_time, action='Nmap_UDP_Scan')
        if scan_res:
            print (scan_res)
            #Calling nmap_result_result_parser to parse scan_result and return service:ports dictinary
            udp_port_service_dict = nmap_result_parser(ip, scan_res, parse_udp=True)
            command_list = scan_the_services(ip, verbosity, udp_port_service_dict=udp_port_service_dict)



    return command_list    #Returning command list to be passed to Master_Command_executor fucntion to call these command in separate tabs of genome-terminal






def nmap_result_parser(ip, scan_result, **kwargs):
    ' It takes scan result from python nmap module which generates it as dictionary and parse it\
    further to print Discovered ports and also rertuns {service:ports} based dictionary '

    ip = ip
    scan_res = scan_result
    service_port_dict = {}
    parse_tcp = False
    parse_udp = False
    state = scan_res['scan'][ip]['status']['state']

    for k, v in kwargs.items():
        if 'parse_tcp' in k:
            parse_tcp = True
            tcp_ports_list = [i for i in scan_res['scan'][ip]['tcp'].keys()]
        if 'parse_udp' in k:
            parse_udp = True
            udp_ports_list = [i for i in scan_res['scan'][ip]['udp'].keys()]

    if parse_tcp:
        for p in tcp_ports_list:
            port_state = scan_res['scan'][ip]['tcp'][p]['state']
            if port_state == 'open':
                print (f'{CLY}[+] {port_state} \t\t\t {CLC} {p} ')
                service_name = scan_res['scan'][ip]['tcp'][p]['name']
                if service_name:
                    try:
                        if service_port_dict[service_name]:
                            pass
                    except Exception as e:
                        service_port_dict[service_name] = []
                    if p not in service_port_dict[service_name]:
                        service_port_dict[service_name].append(p)              

                    print (f'{CLY}    service-Name \t\t {CLC}{service_name} ')
                    if (service_name == 'http' or service_name == 'https'):
                        try:
                            http_title = scan_res['scan'][ip]['tcp'][p]['script']['http-title']
                            print (f'    {CLY}HTTP-Title \t\t {CLC}{http_title} ')
                        except Exception as e:
                            print (f'    {CR}HTTP-Title \t\t {CLR} Could not be found ')

                    service_version = scan_res['scan'][ip]['tcp'][p]['version']
                    print (f'{CLY}    service-Version \t\t {CLC}{service_version} ')
                    product_name = scan_res['scan'][ip]['tcp'][p]['product']
                    print (f'{CLY}    Product-Name \t\t {CLC}{product_name} \n\n')


    if parse_udp:
        for p in udp_ports_list:
            port_state = scan_res['scan'][ip]['udp'][p]['state']
            if port_state == 'open':
                print (f'{CLY}[+] {port_state} \t\t\t {CLC} {p} ')
                service_name = scan_res['scan'][ip]['udp'][p]['name']
                if service_name:
                    try:
                        if service_port_dict[service_name]:
                            pass
                    except Exception as e:
                        service_port_dict[service_name] = []
                    if p not in service_port_dict[service_name]:
                        service_port_dict[service_name].append(p)  

                    print (f'{CLY}    Service-Name \t\t {CLC}{service_name} ')
                    if (service_name == 'http' or service_name == 'https'):
                        http_title = scan_res['scan'][ip]['udp'][p]['script']['http-title']
                        print (f'{CLY}    HTTP-Title \t\t {CLC}{http_title} ')
                    service_version = scan_res['scan'][ip]['udp'][p]['version']
                    print (f'{CLY}    service-Version \t\t {CLC}{service_version} ')
                    product_name = scan_res['scan'][ip]['udp'][p]['product']
                    print (f'{CLY}    Product-Name \t\t {CLC}{product_name} \n\n')



    return service_port_dict




def scan_the_services(ip, verbosity, **kwargs):

    'It takes service port dictionary returned by nmap parser functions and itrate of the the services\
       and port to identify if any serice is there running on what ports and then CLReate a command string\
       to be furhter passet to Multi_bash_command_executor fucntion as a list of commands to execute in\
       separate tabs of the terminal.'

    ip = ip
    verbosity = verbosity
    tcp_services = False
    udp_services = False
    global command_list

    for k, v in kwargs.items():
        if 'tcp_port_service_dict' in k:
             tcp_port_service_dict = kwargs[k]
             tcp_services = True
        elif 'udp_port_service_dict' in k:
            tcp_port_service_dict = kwargs[k]
            udp_sercices = True

        
    if tcp_services:
        for service in tcp_port_service_dict:
            port_list = tcp_port_service_dict[service]
            go_throuh_services(ip, service, port_list, verbosity, protocol_type='TCP')

    if udp_services:
        for service in udp_port_service_dict:
            port_list = udp_port_service_dict[service]
            go_throuh_services(ip, service, port_list, verbosity, protocol_type='UDP')


    #print (f'{CLW}[*] Execution Multi_bash_command_executor withing scan_the service fucntion. command_list is already passed.')
    Multi_Bash_Command_Executer(command_list)  #Command list has already been created by go_throug_services function. Its time to call command list by multi_bash_command_execurot function to execute all in different bash shells
    return 




#service -SCANNING

def go_throuh_services(ip, service, port_list, verbosity, protocol_type='p_type'):


    ip = ip
    service = service
    ports = port_list
    protocol_type = protocol_type


    global username_path
    global password_path
    global gobust_word_list_path



    def quick_path_check(file_path):
        ok = False
        path = Path(file_path)
        if Path.is_file(path):
            ok = True
            return ok
        else:
            return ok



    # go through the service dictionary to call additional targeted enumeration functions
    for port in  ports:

        print('\n' * 1)
        if (service == 'http') or (service == 'http-proxy') or (service == 'http-alt') or (service == 'http?'):
            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            Banner_Grabber(port, service, ip, protocol_type)

            gobust_word_list_path_ok = quick_path_check(gobust_word_list_path)

            if gobust_word_list_path_ok:
                #GOBUST = f'gobuster dir -e -u http://{ip}:{port} -w {gobust_word_list_path} -k -l -a "Mozilla/5.0 (X11; linux x86_64; rv:38.0) Gecko/200100101 Firefox/38.0 Iceweasel/38.8.0" -o /{output_path}/gobust-{ip}_{port}.txt -s 200,204,301,302,307,403'
                WFUZZ = f'wfuzz -c -w {gobust_word_list_path} --hc 404 http://{ip}:{port}/FUZZ | tee {output_path}/wfuzz_{ip}_http_{port}.txt'
                command_list.append(WFUZZ)

                if verbosity:
                    print(f'           {CY} COMMAND: {CW} {WFUZZ} \n') 
            else:
                if not gobust_word_list_path_ok:
                    print(f'{CLR}[+] {CLR} MISSING username_path: {CLB} {username_path}')
                    print(f'           {CLR}Exited Execution of {CY} COMMAND: {CLB} {WFUZZ} \n') 

             
            NIKTOSCAN = f'nikto -C all -h http://{ip}:{port} -o {output_path}/nikto_{ip}_http_{port}.txt'
            command_list.append(NIKTOSCAN)
            if verbosity:
                print(f'           {CY} COMMAND: {CW} {NIKTOSCAN} \n') 

            CURLSCAN = f'curl -I http://{ip}:{port} | tee {output_path}/curlscan_result_http_{ip}_{port}'
            command_list.append(CURLSCAN)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {CURLSCAN} \n') 

            HTTPSCAN = f'nmap -Pn -sSV -A -vv --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -p {port} --script=http-brute.nse,http-cookie-flags.nse,http-default-accounts,http-devframework.nse,http-enum.nse,http-fileupload-exploiter.nse,http-form-brute.nse,http-form-fuzzer.nse,http-iis-short-name-brute.nse,http-method-tamper.nse,http-methods.nse,http-ntlm-info.nse,http-passwd.nse,http-phpmyadmin-dir-traversal.nse,http-proxy-brute.nse,http-put.nse,http-rfi-spider.nse,http-robots.txt.nse,http-security-headers.nse,http-server-header.nse,http-shellshock.nse,http-userdir-enum.nse,http-vhosts.nse,http-waf-detect.nse,http-waf-fingerprint.nse,http-webdav-scan.nse,http-wordpress-brute.nse,http-wordpress-enum.nse,http-wordpress-users.nse -oN {output_path}/{ip}_http_nmap_script_results_{port} {ip}'
            command_list.append(HTTPSCAN)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {HTTPSCAN} \n') 

            SQLI_TEST = f'nmap -p {port} --script=http-sql-injection.nse -oN {output_path}/{ip}_http_sql_injection_{port} {ip}'
            command_list.append(SQLI_TEST)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {SQLI_TEST} \n') 
    
                #LFI = f'my_fimap.py {ip} {p} {protocol}  | tee {output_path}/lfi_{p}'
                #print(f'CLG[*]S_RST {CLB} {LFI} \n')


        elif (service == 'ssl/http') or ('https' == service) or ('https?' == service):
            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            Banner_Grabber(port, service, ip, protocol_type)

            SSLSCAN = f'sslscan {ip}:{port} | tee {output_path}/ssl_scan_{ip}_{port}'

            command_list.append(SSLSCAN)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {SSLSCAN}\n') 

            #DIRBSCAN_https = f'dirb https://{ip}:{port} -o /{output_path}/dirb-{ip}_{port}.txt -r'
            #print(f'CLG[*]S_RST {CLB} {DIRBSCAN_https} \n')
            #command_list.append(DIRBSCAN_https)

            gobust_word_list_path_ok = quick_path_check(gobust_word_list_path)

            if gobust_word_list_path_ok:
                #GOBUSTs = f'gobuster dir -e -u https://{ip}:{port} -w {gobust_word_list_path} -k -l -a "Mozilla/5.0 (X11; linux x86_64; rv:38.0) Gecko/200100101 Firefox/38.0 Iceweasel/38.8.0" -o /{output_path}/gobust-{ip}_{port}.txt -s 200,204,301,302,307,403'
                WFUZZs = f'wfuzz -c -w {gobust_word_list_path} --hc 404 http://{ip}:{port}/FUZZ | tee {output_path}/wfuzz_{ip}_https_{port}.txt'
                command_list.append(WFUZZs)

                if verbosity:
                    print(f'           {CY} COMMAND: {CW} {WFUZZs}\n') 
            else:
                if not gobust_word_list_path_ok:
                    print(f'{CLR}[+] {CLR} MISSING username_path: {CLB} {gobust_word_list_path}')
                    print(f'           {CLR}[+] Exited Execution of {CY} COMMAND: {CLB} {WFUZZs} \n') 



            NIKTOSCAN_https = f'nikto -C all -h https://{ip}:{port} -o {output_path}/nikto-https-{ip}_{port}.txt'
            command_list.append(NIKTOSCAN_https)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {WFUZZs}\n') 

            CURLSCAN_https = f'curl -I https://{ip}:{port} | tee  {output_path}/curlscan_result_https_{ip}_{port}.txt'
            command_list.append(CURLSCAN_https)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {CURLSCAN_https}\n') 

            HTTP_SCAN_https = f'nmap -Pn -sSV -A -vv --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -p {port} --script=http-brute.nse,http-cookie-flags.nse,http-default-aclCounts.nse,http-devframework.nse,http-enum.nse,http-fileupload-exploiter.nse,http-form-brute.nse,http-form-fuzzer.nse,http-iis-short-name-brute.nse,http-method-tamper.nse,http-methods.nse,http-ntlm-info.nse,http-passwd.nse,http-phpmyadmin-dir-traversal.nse,http-proxy-brute.nse,http-put.nse,http-rfi-spider.nse,http-robots.txt.nse,http-security-headers.nse,http-server-header.nse,http-shellshock.nse,http-userdir-enum.nse,http-vhosts.nse,http-waf-detect.nse,http-waf-fingerprint.nse,http-webdav-scan.nse,http-wordpress-brute.nse,http-wordpress-enum.nse,http-wordpress-users.nse -oN {output_path}/{ip}_https_nmap_script_results_{port} {ip}'
            command_list.append(HTTP_SCAN_https)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {HTTP_SCAN_https}\n') 

            SQLI_TEST = f'nmap -p {port} --script=http-sql-injection.nse -oN {output_path}/{ip}_https_sql_injection_{port} {ip}'
            command_list.append(SQLI_TEST)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {SQLI_TEST}\n') 
            #LFIs = 'my_fimap.py {ip} {p} {protocol}  | tee /{newdir}/lfi_{p}'.format(ip=ip, p=s, newdir=newdir, protocol='https')
            #scan_type = 'LFIs'
                

        elif 'smtp' in service:
            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            Banner_Grabber(port, service, ip, protocol_type)

            SMTP_SCAN = f'nmap -sV -Pn -p {port} --script=smtp-commands,smtp-enum-users,smtp-open-relay.nse,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,smtp-strangeport.nse -oN {output_path}/smtp_{ip}_nmap_SMTP_script_result_{port}.txt {ip}'
            command_list.append(SMTP_SCAN)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {SMTP_SCAN}\n') 

            SMTP_BRUTE = f'nmap -sV -Pn -p {port} --script=smtp-brute.nse -oN {output_path}/smtp_{ip}_nmap_SMTP_script_result_{port}.txt {ip}'
            command_list.append(SMTP_BRUTE)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {SMTP_SCAN}\n') 


            message = f'''           {CLY}    Use below modes to check for the users if allowed by smtp serviceer\n
                                              {CLC}EXPN\n
                                              {CLC}VRFY\n
                                              {CLC}RCPT\n
               {CY}example: \'smtp-user-enum -M VRFY -U /usr/share/wordlists/fuzzdb/wordlists-user-passwd/names/namelist.txt -t {ip} -p {port} | tee output_path/smtp_user_enum_VRFY_{ip}_{port}.txt\''''
            
            print(f'{CLG}[*] {CY} Please execute below command for SMTP manual enumaration')
            print(f'           {CY} COMMAND: {CW} {messaage} \n')
         


        elif 'ftp' in service:

            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            Banner_Grabber(port, service, ip, protocol_type)

            FTPSCAN = f'nmap -sV -Pn -vv -p {port} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN {output_path}/ftp_{ip}_nmap_FTP_scripts_result_{port} {ip}'
            command_list.append(FTPSCAN)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {FTPSCAN}\n') 
          
            username_path_ok = quick_path_check(username_path)
            password_path_ok = quick_path_check(password_path)

            if username_path_ok and username_path_ok:
                FTPBRUTE = f'medusa -h {ip} -u {username_path} -P {password_path} -e ns -n {port} -f -M {service} -O {output_path}/{ip}_medusa_{port}'
                command_list.append(FTPBRUTE)
                if verbosity:
                    print(f'           {CY} COMMAND: {CW} {FTPBRUTE}\n') 
            else:
                if not username_path_ok:
                    print(f'{CLR}[+] {CLR} MISSING username_path: {CLB} {username_path}')
                    print(f'           {CLR}[+] Exited Execution of {CY} COMMAND: {CLB} {FTPBRUTE} \n') 
                elif not password_path_ok:
                    print(f'{CLR}[+] {CLR} MISSING password_path: {CLB} {password_path}')
                    print(f'           {CLR}[+] Exited Execution of {CY} COMMAND: {CLB} {FTPBRUTE} \n') 
                




        elif ('rpcbind' in service) or ('nfs' in service) or ('mountd' in service) or ('portmapper' in service):

            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            nfs(ip, port, service)



        elif 'snmp' in service:

            common_community_strings = '''
                                            #public
                                            #private
                                            #community '''


            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            SNMP_ENUM = f'nmap -vv -sV -sU -Pn -p {port} --script=snmp-netstat,snmp-processes,snmp-info -oN {output_path}/{ip}_SNMP_Enum_{port} {ip}; echo; snmp-check -p {port} -c public {ip}; echo; echo; snmp-check -p {port} -c private {ip}; echo; echo; snmp-check -p {port} -c community {ip}'

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {SNMP_ENUM}\n') 

            print(f'           {CC} Try SNMPWALK or onesixtyone with below community strings')
            print(f'                   {CC} {common_community_strings}\n')

            command_list.append(SNMP_ENUM)



        elif ('Oracle' in service) or ('oracle' in service):

            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')


            Banner_Grabber(port, service, ip, protocol_type)
            ORACLE_VERSION = f'tnscmd10g version -p {port} -h {ip} --logfile {output_path}/Oracle_{ip}_version_result_{port};echo;echo;'
            ORACLE_STATUS = f'tnscmd10g status -p {port} -h {ip} --logfile {output_path}/Oracle_{ip}_version_result_{port}'
            ORACLE_SCAN = f'{ORACLE_VERSION};echo\'\n\n\n\'&&&{ORACLE_STATUS}'
            if verbosity:
                print(f'           {CY} COMMAND: {CW} {ORACLE_VERSION}\n\n') 
                print(f'           {CY} COMMAND: {CW} {ORACLE_STATUS}\n') 

            command_list.append(ORACLE_SCAN)



        elif 'zeroconf' in service or 'mDNS' in service or 'MDNS' in service or 'domain' in service:

            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')


            Banner_Grabber(port, service, ip, protocol_type)
            ZEROCONF_SCAN = f'nmap --script=dns-service-discovery -p {port}  -oN {output_path}/{ip}_zero_conf_nmap_result_{port} {ip}' % (s, newdir, ip_address, s, ip_address)
            dns_file_path = '/usr/share/wordlists/fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt'
            ok = quick_file_check(dns_file_path)
            if ok:
                ZONE_ZXFR = f'dnsrecon -d {ip} --threads 50 -D /usr/share/wordlists/fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt -x {output_path}/{ip}_dnscecon_{port}'

                if verbosity:
                    print(f'           {CY} COMMAND: {CW} {ZONE_ZXFR}\n') 
                    command_list.append(ZONE_ZXFR)
            else:
                print(f'               {CR}[+] {CY} File not found for Dns-Zone-Transfer: "{dns_file_path }" \n') 


            message = f'{CLC}    PLEASE PROVIDE DNS Service Name for DNS-XONE-TRANSFER: '
            DNS_Server_Name  = raw_input(message)

            if (DNS_Server_Name is not None) or  (DNS_Server_Name != ''):
                ZONE_ZXFR = f'host -t axfr {ip} {DNS_Server_Name} | tee {output_path}/{ip}_dnscecon_{port}'
                command_list.append(ZONE_ZXFR)

                if verbosity:
                    print(f'           {CY} COMMAND: {CW} {ZONE_ZXFR}\n') 
            else:
                print(f'               {CR}    Correnct DNS Server-Name Not provided. please execute below command manually.')
                print(f'               {CY}    COMMAND: {CW} host -t axfr {ip} DNS-Server-Name | tee {output_path}/{ip}_dnscecon_{port} \n') 






        elif ("pop3" in service) or ("pop3s" in service):

            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')


            Banner_Grabber(port, service, ip, protocol_type)

            Cmd_To_Try_message = f'''{CB}
                       telnet {ip} {port}
                       USER user_name@{ip}
                       PASS password

                            or:

                       USER user_name
                       PASS admin

                       # List all emails
                       list

                       # Retrieve email number 5, for example
                       retr 9
                              '''

            POP3_BRUTE = f'nmap -p {port} --script=pop3-brute.nse -oN {output_path}/{ip}_POP3_brute_{port} {ip}'
            print(f'{CLG}[+] {CY} COMMAND: {CC} {ZONE_ZXFR} \n') 

            command_list.append(SNMP_ENUM)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {ZONE_ZXFR}\n') 

            print(f'{CLG}[*] {CY} Commands to run to Connect to POP3 serviceer manually')
            print(f'        {CLB}{Cmd_To_Try-message}\n')



        elif ('microsoft-ds' in service) or ('netbios-ns' in service) or ('netbios-ssn' in service):

            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')


            ENUM_4_LINUX = f'enum4linux -a -v {ip} | tee  {output_path}/enum4linux_result_{ip}_{port}'
            SMB_NMAP = f'nmap -sV -Pn -p {port} --script=smb-double-pulsar-backdoor.nse,smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-flood.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-protocols.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb2-capabilities.nse,smb2-security-mode.nse,smb2-time.nse,smb2-vuln-uptime.nse -oN {output_path}/smb_{ip}_{port}_nmap {ip}'
            print(f'           {CY} COMMAND: {CW} {ENUM_4_LINUX} \n') 
            print(f'           {CY} COMMAND: {CW} {SMB_NMAP} \n') 

            command_list.append(ENUM_4_LINUX)
            command_list.append(SMB_NMAP)
            if verbosity:
                print(f'           {CY} COMMAND: {CW} {ENUM_4_LINUX}\n') 
                print(f'           {CY} COMMAND: {CW} {SMB_NMAP}\n') 

            smb_share_and_file_list(ip, port)
            #try:
            #    smb_share_and_file_list(ip, port)
            #except Exception as e:
            #    print (f'{CLR}[-] something went wrong in executing smb_share_and_file_list func - please read error as below')
            #    print (f'{CR}[-]     {e}')


        elif "mysql" in service:


            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            Banner_Grabber(port, service, ip, protocol_type)

            MY_SQL_ENUM = f'nmap -sV -Pn -p {port} --script=mysql-databases.nse,mysql-dump-hashes.nse --script-args=mssql.instance-port=%s,smsql.username-sa,mssql.password-sa,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-query.nse,mysql-users.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse -oN {output_path}/{ip}_mssql_enum_{port} {ip}'
            MY_SQL_BRUTE = f'nmap -sV -Pn -p {port} --script=mysql-audit.nse,mysql-brute.nse -oN {output_path}/{ip}_mssql_brute_{port} {ip}'

            command_list.append(MY_SQL_ENUM)
            command_list.append(MY_SQL_BRUTE)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {MY_SQL_ENUM}\n')
                print(f'           {CY} COMMAND: {CW} {MY_SQL_BRUTE}\n') 


        elif ("ms-sql" in service) or ("mssql" in service):

            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')
            
            Banner_Grabber(port, service, ip, protocol_type)

            MS_SQL_ENUM = f'nmap -sV -Pn -p {port} --script=broadcast-ms-sql-discover.nse,ms-sql-config.nse,ms-sql-dac.nse,ms-sql-dump-hashes.nse --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa,ms-sql-empty-password.nse,ms-sql-hasdbaccess.nse,ms-sql-info.nse,ms-sql-ntlm-info.nse,ms-sql-query.nse,ms-sql-tables.nse,ms-sql-xp-cmdshell.nse -oN {output_path}/{ip}_ms-sql_enum_{port} {ip}'           
            MS_SQL_BRUTE = f'nmap -sV -Pn -p {port} --script=ms-sql-brute.nse -oN {output_path}/{ip}_ms-sql_brute_{port} {ip}'

            command_list.append(MS_SQL_ENUM)
            command_list.append(MS_SQL_BRUTE)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {MS_SQL_ENUM}\n')
                print(f'           {CY} COMMAND: {CW} {MS_SQL_BRUTE}\n') 

        elif "ssh" in service:


            print(f'\n{CLG}[*] {CLY}{service}  {CY}service found on  {CLC}{ip}: {port}')
            print(f'         {CG} Generating the associated commands as below for further scan...\n')

            Banner_Grabber(port, service, ip, protocol_type)

            SSHENUM = f'nmap -sV -Pn -p {port} --script=ssh-auth-methods.nse,ssh-hostkey.nse,ssh-publickey-acceptance.nse,ssh-run.nse,ssh2-enum-algos.nse,sshv1.nse -oN {output_path}/{ip}_ms-sql_brute_{port} {ip}'
            command_list.append(SSHENUM)

            if verbosity:
                print(f'           {CY} COMMAND: {CW} {SSHENUM}\n')

            #SSHBRUTE = f'medusa -h {ip} -u {username_path} -P {password_path} -e ns -n {port} -f -M {service} -O {output_path}/{ip}_medusa_{port}'
            # (ns) n no pass, s same pass as username, -n no default port if ssh runs on non default port -M module_name like ssh http etc

            username_path_ok = quick_path_check(username_path)
            password_path_ok = quick_path_check(password_path)

            if username_path_ok and username_path_ok:
                SSHBRUTE = f'medusa -h {ip} -u {username_path} -P {password_path} -e ns -n {port} -f -M {service} -O {output_path}/{ip}_ssh_{port}'
                command_list.append(SSHBRUTE)

                if verbosity:
                    print(f'           {CY} COMMAND: {CW} {SSHBRUTE}\n')
            else:
                if not username_path_ok:
                    print(f'           {CLR}[+] {CLR} MISSING username_path: {CLB} {username_path}')
                    print(f'           {CLR}[+] Exited Execution of {CY} COMMAND: {CLR} {SSHBRUTE} \n') 
                elif not password_path_ok:
                    print(f'           {CLR}[+] {CLR} MISSING password_path: {CLB} {password_path}')
                    print(f'           {CLR}[+] Exited Execution of {CY} COMMAND: {CLR} {SSHBRUTE} \n') 
                



    return








def main():

    #hand()

    #Global valirable declaration
    global udp_port_string
    global udp_open_filtered_port_string
    global command_list
    global closed_confirmed_port_list
    global username_path
    global password_path
    global gobust_word_list_path
    global file_path_list
    global output_path
    global opne_but_not_confirmed_ports
    global file_path

    verbosity = False

    print (banner)
    time.sleep(1)

    args = argumentParser()
    if args.V:
        print (args.V)

    if 'IP' in args and not args.IP is False:
        ip = args.IP

    if 'P' in args and not args.P is False:
        port = args.P

    if 'R' in args and not args.R is False:
        port_range = args.R
        #Parcing port range 1-65535  (range_start = 1, range_end = 65535)
        start, end = PortRangeParser(port_range)

    if 'F' in args and not args.F is False:
        file_path = args.T
        port_from_file_parser(file_path)

    if 'S' in args and not args.S is False:
        port_sequence = args.S
        ports_sequence_list = port_sequence_parser(port_sequence)

    if 'T' in args:
        protocol_type = args.T

    if 'M' in args:
        scan_method = args.M

    if 'N' in args:
        nThread = int(args.N)

    if 'O' in args:
        dir_path = args.O

    if args.V:
        verbosity = True

    #File-Dir Paths used in the script
    username_path = '/root/Desktop/My_share/Dropbox/OSCP/wordlist_mine/my_username_list.txt'
    password_path = '/root/Desktop/My_share/Dropbox/OSCP/wordlist_mine/my_password_list.txt'
    gobust_word_list_path = '/usr/share/wordlists/dirb/common.txt' #/dirbuster/directory-list-2.3-medium.txt'
    file_path = [username_path, password_path, gobust_word_list_path]


    #Validating File-Dir Paths used in this script
    file_path_list = file_checker(file_path)

    #Checking and Creating Folder for output_file
    output_path = dir_creator(dir_path)




    if args.R:
        multi_port_lists = generate_multi_port_list(nThread, start=start, end=end)


    #TCP parsing string
    if  protocol_type == 'TCP':
        print (f'{CLM}[*] {CLY} TCP {CLG}port scan STARTED....\n')
        start_time = time_duration_caculator('start', action='TCP_PORT_SCAN', previous_start_time=None)
        print (f'{CLM}[*] {CLY} STAT-TIME of scan:  {CLM}{start_time}\n')

        #Defining argument setter function that will hold a place holder into it and return the given function set with that place holder that will latter be filled will an argument to execute.
        if scan_method == 'python':
            def arg_setter(place_holder_for_port_or_port_list):
                return scan_port_with_python(ip, place_holder_for_port_or_port_list, 'TCP', flag='S', retries=0)


            #Scanning ports with python based port scanning function
            if args.R and multi_port_lists:
                for port_list in multi_port_lists:
                    tcp_future_executor(arg_setter, port_list, nThread)
            elif args.P:
                tcp_future_executor(arg_setter, port, nThread)
            elif args.S and ports_sequence_list:
                port_seq_list = generate_multi_port_list(nThread, port_list=ports_sequence_list)
                for port_list in port_seq_list:
                    if port_list != '':
                        tcp_future_executor(arg_setter, port_list, nThread)

                    # Calling the Ginnie to do the magic automatically calling several functions one by another.
        

        elif scan_method == 'nmap':
            if args.P and port:
                scan_with_nmap(ip, port, verbosity, 'TCP')
            elif args.R and port_range:
                scan_with_nmap(ip, port_range, verbosity, 'TCP')
            elif args.S and port_sequence:
                 scan_with_nmap(ip, port_sequence, verbosity, 'TCP')
            

        #printing parsed ports on screen
        if protocol_type == 'TCP':
            if tcp_port_string:
                print (f'\n{CG}[+] Open Ports ...\n')
                for port in tcp_port_string.split(','):
                    if port != '':
                        print (f'           {CY} {port}/TCP: {CLY} OPEN')
                print
                time_duration_caculator('end', action='TCP_PORT_SCAN', previous_start_time=start_time)
            else:
                print (f'{CLR}[-] {CR} NO TCP PORT FOUND. Exiting the script.....')
                print (f'{sorry}\n')


    if tcp_port_string:
        scan_with_python_nmap(ip, verbosity, tcp_port_string=tcp_port_string, scan_tcp='scan_tcp')




    #UDP parsing string
    if  protocol_type == 'UDP':

        print (f'\n{CLM}[*] {CLY} UDP {CLM}Port Scan Starting....\n')
        start_time = time_duration_caculator('start', action='SCAPY_UDP_PORT_SCAN', previous_start_time=None)
        print (f'\n{CLM}[*] {CLY} START-TIME of scan:  {CLM}{start_time}....\n')

        if scan_method == 'python':
            #Defining argument setter function that will hold a place holder into it and return the given function set with that place holder that will latter be filled will an argument to execute.
            def arg_setter(place_holder_for_port_or_port_list):
                return scan_port_with_python(ip, place_holder_for_port_or_port_list, 'UDP', flag='S', retries=0)  #In UDP Flag is not required but in TCP it would be rerquired hence it is set with function but will not be used in UDP scan



            #port_parser('default_udp_ports')
            if args.R and multi_port_lists:  #It is when a port range is provided through command line
                for port_list in multi_port_lists:
                    if port_list != '':
                        udp_future_executor(arg_setter, port_list, nThread)
            elif args.P and port:
                udp_future_executor(arg_setter, port, nThread)
            elif args.F and ports_sequence_list:
                port_file_list = generate_multi_port_list(nThread, port_list=port_list_generated_from_passed_file)
                for port_list in port_file_list:
                    if port_list != '':
                        udp_future_executor(arg_setter, port_list, nThread)
            elif args.S and ports_sequence_list:
                port_seq_list = generate_multi_port_list(nThread, port_list=ports_sequence_list)
                for port_list in port_file_list:
                    if port_list != '':
                        udp_future_executor(arg_setter, port_list, nThread)



            #nested function
            def loop_for_udp(udp_ports_to_be_rescanned):

                if udp_ports_to_be_rescanned:
                    if len(udp_ports_to_be_rescanned) > nThread:
                        multi_port_list = generate_multi_port_list(nThread, udp_ports_to_be_rescanned)
                        for port_list in multi_port_list:
                            udp_future_executor(arg_setter, port_list, nThread)
                    else:
                        udp_future_executor(arg_setter, udp_ports_to_be_rescanned, nThread)
                return

                    
            for _ in range(1):
                loop_for_udp(udp_ports_to_be_rescanned)



        elif scan_method == 'nmap':
            if args.P and port:
                scan_with_nmap(ip, port, verbosity, 'UDP')
            elif args.R and port_range:
                scan_with_nmap(ip, port_range, verbosity, 'UDP')
            elif args.S and port_sequence:
                scan_with_nmap(ip, verbosity, port_sequence, verbosity, 'UDP')
            



    #printing parsed ports on screen
    if protocol_type == 'UDP':
        if udp_port_string:
            for port in udp_port_string.split(','):
                if port != '':
                        print (f'\n{CG}[+] Open Ports ...\n')
                        print (f'           {CY} {port}/UDP: {CLY} OPEN')
            print
            time_duration_caculator('end', action='UDP_PORT_SCAN', previous_start_time=start_time)

        else:
            print (f'{CLR}[-] {CR} NO UDP PORT FOUND. Exiting the script.....')
            print (f'{sorry}\n')
    

    # Calling the Ginnie to do the magic and automatically calling several functions one by another.
    if udp_port_string:
        scan_with_python_nmap(ip, verbosity, udp_port_string=udp_port_string, scan_udp='scan_udp')






if __name__=='__main__':
    main()













