import nmap
nm = nmap.PortScanner()

nm.scan(hosts='192.168.1.0/24', arguments='-n -sP')
cmd = nm.command_line()
print ('\n' + 'Running nmap command: '+ cmd + '\n')
print ('Hosts found: ')

hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

for host, status in hosts_list:
    print(host + ' ' + status)
