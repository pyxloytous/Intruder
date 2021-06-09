# Intruder
     _____________________________________________________________________________________________________
     //----------------------------------------------------------------------------------------------------\\
     ||                                                                                                    || 
     ||   8888888 888b    888 88888888888 8888888b.  888     888 8888888b.  8888888888 8888888b            ||
     ||     888   8888b   888     888     888   Y88b 888     888 888  "Y88b 888        888   Y88b          ||
     ||     888   88888b  888     888     888    888 888     888 888    888 888        888    888          ||
     ||     888   888Y88b 888     888     888   d88P 888     888 888    888 8888888    888   d88P          ||
     ||     888   888 Y88b888     888     8888888P"  888     888 888    888 888        8888888P            ||         
     ||     888   888  Y88888     888     888 T88b   888     888 888    888 888        888 T88b            ||
     ||     888   888   Y8888     888     888  T88b  Y88b. .d88P 888  .d88P 888        888  T88b           || 
     ||   8888888 888    Y888     888     888   T88b  "Y88888P"  8888888P"  8888888888 888   T88b          ||
     ||                                                                                                    ||
     ||                              +-+-+-+-+-+-+-+-+-+-+-+-+-+                                           ||
     ||                              |T|H|E| |A|U|T|O|M|A|T|E|R|                                           ||
     ||                              +-+-+-+-+-+-+-+-+-+-+-+-+-+                                           ||
     ||                                                                                                    ||
     ||                                      +-+-+-+-+                                                     ||
     ||                                      |f|r|o|m|                                                     ||
     ||                                      +-+-+-+-+                                                     ||
     ||                                                                                                    ||
     ||                      +-+-+-+-+-+-+-+--+-+--+-+-+-+-+-+-+-+-+-+-+-+                                 ||
     ||                      |p|y|x|l|o|y|t|o|u|s| |@| |g|m|a|i|l|.|c|o|m|                                 ||
     ||                      +-+-+-+-+-+-+-+-+-+-+--+--+-+-+-+-+-+-+-+-+-+                                 ||
     \\____________________________________________________________________________________________________//
      -----------------------------------------------------------------------------------------------------
      

A CTF scanner that automates the task from port scanning to assessing several services on the target.

It has almost all the ability that is found in several other scripts in the wild like this.

What makes it different is that it facilitates us to see the output of ongoing scans in separate terminal tabs.

This functionality gives this an enhanced ability to allow someone for continue his work based on the output he starts getting instead keep waiting for a long time to let the all scripts finish and then see what outcome they have brought in terminal.

Nmap is a powerful tool for port scanning and service scanning also but in some situation during scan it becomes too slow or almost gets stuck. To deal with this, this script has a feature been introduced to it that works purely on python.

A python scapy based port scanner has been introduced to tackle the situation where nmap starts failing. Though python does not have that much concurrency compared to lua the nmap is scripted on but something is better than nothing and this allows one to continue his work other than keep waiting for a long time or get stuck totally.






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
    
    Example : python3 IntruDer.py -IP 192.168.116.131 -R 1-65535 -N 100 -T TCP -O /root/Desktop/test -M nmap  - (Initial scanning with nmap)
    Example:  python3 IntruDer.py -IP 192.168.116.131 -R 1-65535 -N 100 -T TCP -O /root/Desktop/test -M python - (Initial scanning with python function )
    
    
