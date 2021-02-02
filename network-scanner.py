#    Copyright (C) 2021 Hani Ragab Hassen

#    This file is part of The HackInABashShell Tools.

#    HackInABashShell is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation version 3 of the License.

#    HackInABashShell is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License along with HackInABashShell. If not, see <https://www.gnu.org/licenses/>.

from platform import system
import subprocess  
import sys
import getopt
from termcolor import colored
from scapy.all import *
import socket
import random

def isValidIP(ip): #a non-regex implementation
	parts=ip.split('.')
	if len(parts)!=4:
		return False
	try:
		ints=[int(p) for p in parts]
	except:
		return False
	for i in ints:
		if (i<0) or (i>255):
			return False
	if ints[0]==0: #a common case?
		return False
	#TODO: Can make further checks to make sure the IP is a usable IP address: e.g., 255.255.255.255 will pass all these tests
	return True

def ping_wrapper(host,n):
	# Linux uses '-c' to specify the number of pings, Windows uses '-n'
	if system().lower()=='windows':
		count='-n'
	else:
		count='-c'
	cmd = ['ping', count, n, host]
	try:
		ret = subprocess.check_output(cmd)
	except: #Failed to connect. TODO: need to check if your interface is up beforehand.
		return False
	return True 

def scan_icmp(ip4_or_hostname,content="Scheduled admin test",cnt=1,time_out=5,v=False):
	#v: verbose
	try:
		ip_a = socket.gethostbyname(ip4_or_hostname)
	except: #check if it's an ip range
		if '-' in ip4_or_hostname:
			ips= ip4_or_hostname.split('-') # e.g., ['192.168.1.1', '127'] (from '192.168.1.1-127')
			try:
				if isValidIP(ips[0]):
					dummy=int(ips[1]) #is this an int? Can be improved.
					icmp_pkts=IP(dst=ip4_or_hostname)/ICMP()/Raw(content)
					ans, unans = sr(icmp_pkts, timeout=time_out,verbose=v) #count=cnt, 
					return ans
			except:
				print('For -H, you can provide either a hostname, IP address, or a range or IP addresses expressed as A.B.C.D-E')
				return []
		elif '/' in ip4_or_hostname: # Can do validation here as above, or leave it to "sr" to raise an exception
			try:
				icmp_pkts=IP(dst=ip4_or_hostname)/ICMP()/Raw(content)
				ans, unans = sr(icmp_pkts, timeout=time_out,verbose=v) #count=cnt, 
				return ans
			except:
				print('For -H, you can provide either a hostname, IP address, or a range or IP addresses expressed as A.B.C.D-E')
				return []

		else:
			print('Error resolving host',ip4_or_hostname)
			return []
	# ip_a is an IP address
	icmp_pkt = IP(dst=ip_a)/ICMP()/Raw(content)
	response=sr1(icmp_pkt, timeout=time_out,verbose=v)
	if response == None:
		return False
	else:
		return True	

def scan_flags():
	#Not optimal, but makes explanation simpler!
	flags=dict()
	flags['ACK']='A'
	flags['A']='A'
	flags['FIN']='F'
	flags['F']='F'
	flags['PSH']='P'
	flags['P']='P'
	flags['RST']='R'
	flags['R']='R'
	flags['SYN']='S'
	flags['S']='S'
	flags['URG']='U'
	flags['U']='U'
	flags['XMAS']='FPU'  #XMAS scan
	flags['X']='FPU'  #XMAS scan
	flags['M']='FA' #Maimon scan
	flags['MAIMON']='FA' #Maimon scan
	return flags	

def scan_TCP_port(ip4_or_hostname,dst_port,s_type,time_out=5,v=False):
	#v: verbose
	try:
		ip_a = socket.gethostbyname(ip4_or_hostname)
	except:
		print("'-H' should be followed by a fully qualified domain name or an IP address")
		sys.exit(2)
	flags=scan_flags()
	ephemeral_port=random.randint(49152,65535) #IANA's recommended range
	pkt=IP()/TCP(flags=flags[s_type.upper()],sport=ephemeral_port)
	pkt.dst=ip_a
	pkt.sport=ephemeral_port
	pkt.dport=int(dst_port)
	response=sr1(pkt, timeout=time_out,verbose=v)
	if not response:
		return 0 #filtered or no host (sometimes, can result from a small value for -t, i.e., the host didn't have enough time to reply)
	else:
		if v:
			response.show() 
		if response.haslayer(TCP):
			if response.getlayer(TCP).flags == 0x14: #RST with ACK (URG ACK PSH RST SYN FIN), https://sites.google.com/site/customconfusion/summary-sheets/tcp-flags
				return 1 #closed (but the host exists, port probably not filtered)
			elif response.getlayer(TCP).flags == 0x12: #SYN with ACK
				return 2 #port open (and host obviously exists)
	if response.haslayer(ICMP): #hadnling possible other responses from a firewall
		if response.src == pkt.dst:
			if int(response.getlayer(ICMP).type)==3: # Destination Unreachable
				if int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]: # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
					
					return 3 # port filtered
		else: # the response we got is not from our original destination
			return 4
	return 5 # Unexpected behavior, a learning opportunity!

def display_help():
	print('Usage: # network-scanner.py -H IP_ADDRESS|FQDN [-p PORT [-s SCAN_TYPE]] [-n MSG_COUNT] [-t TIME_OUT]')

def parse_params(argv):
	try: 
		opts, args = getopt.getopt(argv,"hvn:a:f:t:H:p:s:t:",["help","verbose","npings=","address=","from=","to=","host=","port=","scan=","timeout="])
	except getopt.GetoptError:
		display_help()
		sys.exit(2)
	params=dict()
	params['n']='2' #By default, try only 2 pings (the first might time-out)
	params['t']=5 #Default timeout
	params['s']='SYN' # default scan type is SYN, requires root.
	params['v']=False # verbose mode is turned off by default
	for opt, arg in opts:
		if opt in ['-n','--npings']:
			params['n']=arg
		elif opt in ['-a','--address']:
			params['a']=arg
		elif opt in ['-H','--host']:
			params['H']=arg
		elif opt in ['-p','--port']:
			params['p']=arg
		elif opt in ['-s','--scan']:
			params['s']=arg.upper() #e.g., "syn" becomes "SYN"
		elif opt in ['-t','--timeout']:
			try:
				params['t']=int(arg)
			except:
				print("'Timeout' must be an integer")
		elif opt in ['-h','--help']:
			display_help()
			sys.exit(0)
		elif opt in ['-v','--verbose']:
			params['v']=True
	return params

def port_status_text(resp):
	# #Not optimal, but makes explanation simpler!
	resp_d=dict()
	resp_d[0]='Filtered (or no host)' #filtered or no host
	resp_d[1]='Closed (Host exists, port probably not filtered)' #closed (but the host exists, port probably not filtered)
	resp_d[2]='Open' #port open (and host obviously exists)
	resp_d[3]='Filtered' # port filtered
	resp_d[4]='Response from an intermediary host' # the response we got is not from our original destination
	resp_d[5]='Unexpected behavior' # Unexpected behavior, a learning opportunity! (e.g., try -s A)
	return resp_d[resp]

def main(argv):
	params=parse_params(argv)
	if 'p' in params: #port scan (note that the order of ifs will naturally ignore -s if used without -p)
		response=scan_TCP_port(params['H'],dst_port=params['p'],s_type=params['s'],time_out=params['t'],v=params['v'])
		if response <4:
			print('Port',params['p'], 'is', port_status_text(response))
		else:
			print('Error: scanning port', params['p'], 'returned', port_status_text(response))
	elif 'H' in params:
		print('\tPinging',params['H'])
		response=scan_icmp(params['H'],content="Scheduled admin test",cnt=params['n'],time_out=params['t'],v=params['v'])
		if response:
			print(colored('Active host(s) found','red'))
			if isinstance(response,SndRcvList):
				print(response.summary())
	else:
		display_help()

if __name__ == "__main__":
	main(sys.argv[1:])

	
#Possible Improvements:
#	- Multi-threaded, offer an option (-T?) to specify the number of threads (e.g., -T 10)
#	- Throttle the number of forged packets
#	- Understand A:B, C, D:E, etc.
#	- Better display of outputs (e.g., number of live stations + their list)
# 	- Do common_ports as a default scan ( suggested common_ports = { 7, 20, 21, 22, 23, 25, 53, 69, 80, 88, 109, 110, 123, 137, 138, 139, 143, 156, 161, \
	#389, 443, 445, 500, 546, 547, 587, 660, 995, 993, 1512, 2086, 2087, 2082, 2083, 3306, 3389, 8443, 10000 })
#	- Improve isValidIP
#	- Allow users to specify source port