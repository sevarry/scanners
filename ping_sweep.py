#!/usr/bin/env python

#created by Ted Eckerman, 2018

import nmap

nm = nmap.PortScanner()
up_list = []
nm.scan(hosts='192.168.1.0/24', arguments='-sP')
cmd = nm.command_line()

hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

for host, status in hosts_list:
    #print(host + ' ' + status)
    up_list.append('%s'%(host))

def portscan(host):
    nm.scan(host, '22-443')
    hostname = nm[host].hostname()
    for proto in nm[host].all_protocols():
        print('------------')
        print(hostname)
        print('------------')
        print('Protocol: %s' % proto)
        
        lport = nm[host][proto].keys()
        lport.sort()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state'])) 
 
for host in up_list:
    portscan(host)
