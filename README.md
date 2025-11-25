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
      

Intruder – Automated CTF & Vulnerability Scanner
The Intruder scanner is a comprehensive tool that automates the entire workflow of Capture the Flag (CTF) reconnaissance and vulnerability assessment — from port scanning to service‑specific exploitation checks.

🔑 Core Capabilities
Dual Port Scanning Approach

TCP scanning is handled by Nmap, leveraging its reliable SYN handshake methodology.

UDP scanning is powered by a Python Scapy‑based engine, which uses ICMP packet analysis to infer port states. After 2–3 retries, if no ICMP Type 3 (Port Unreachable) messages are received, the port is assumed to be reachable/open, and further probes are sent to identify running services. This makes UDP scanning faster and more resilient than Nmap’s default UDP process.

👉Service‑Aware Vulnerability Scanning

Once open ports are identified, the script automatically invokes targeted scanners such as HTTP analyzers, SSL testers, SQL injection probes, and more, tailoring assessments to the detected services.

👉Parallel Execution in Separate Tabs

Each scan runs in its own terminal tab, allowing results to stream in real time. Analysts can begin reviewing findings immediately instead of waiting for all scripts to finish, dramatically reducing idle time and improving workflow efficiency.

🚀 Differentiators
Unlike many existing scripts, Intruder combines real‑time visibility, Scapy‑based UDP resilience, and multi‑scanner orchestration. This design ensures that users can continue working productively even when Nmap slows down or stalls, while simultaneously gathering vulnerability insights across multiple services.

👉 In short: Intruder automates reconnaissance, accelerates UDP scanning with Scapy, and orchestrates multiple vulnerability checks in parallel tabs — enabling faster, more efficient CTF and penetration testing workflows.





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
    
    
    
    
    A glimps of the execution of this script
    ----------------------------------------
    
    # intruder -IP 192.168.150.26 -R 1-65535 -N 100 -T TCP -O /root/Desktop/test/Tico/development_test -M nmap     


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



        
 [+] IP-Address:  192.168.150.26
 
 [+] PORT-RANGE:  1-65535
 
 [+] THREADS (-N) set to DEFAULT:  100
 
 [+] PROTOCOL-TYPE:  TCP
 
 [+] SCANNER-TYPE:  nmap
 
 [+] OUT-PUT path for Nmap Result:  /root/Desktop/test/development_test




[+]  Below word-list files is/are present - Good to go :) 

	"/root/Desktop/My_share/Dropbox/OSCP/wordlist_mine/my_username_list.txt"

	"/root/Desktop/My_share/Dropbox/OSCP/wordlist_mine/my_password_list.txt"

	"/usr/share/wordlists/dirb/common.txt"

[+]  Below FOLDER to save output of verious scripts present - Good to go :) 

	 /root/Desktop/test/development_test  

[*]  TCP port scan STARTED....

[*]  STAT-TIME of scan:  2021-06-09 04:00:05

[*] Starting TCP-light port scan on 192.168.150.26: 1-65535

