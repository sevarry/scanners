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
    result = nm[host].hostname()
    print (host + ' : ' + result)
    
for host in up_list:
    portscan(host)
