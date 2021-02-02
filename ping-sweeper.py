#    Copyright (C) 2021 Hani Ragab Hassen

#    This file is part of The HackInABashShell Tools.

#    HackInABashShell is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation version 3 of the License.

#    HackInABashShell is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License along with HackInABashShell. If not, see <https://www.gnu.org/licenses/>.

import platform    
import subprocess  
import sys
import getopt
from termcolor import colored
import socket
#interesting: importing scapy here causes an error with "platform.system().lower()": "AttributeError: 'str' object has no attribute 'system'"

def ping_wrapper(host,n):
	# Linux uses '-c' to specify the number of pings, Windows uses '-n'
	if platform.system().lower()=='windows':
		count='-n'
	else:
		count='-c'
	cmd = ['ping', count, n, host]
	#ret = subprocess.run(cmd, capture_output=True, text=True).stdout
	try:
		ret = subprocess.check_output(cmd)
	except: #Failed to connect. TODO: need to check if your interface is up beforehand.
		return False
	return True 


def main(argv):
	#print('# of arguments is:', len(argv))
	#print('Args list:', str(argv))
	try:
		opts, args = getopt.getopt(argv,"n:a:f:t:",["npings=","address=","from=","to="])
	except getopt.GetoptError:
		print('ping-sweeper.py -a IP_ADDRESS [-n PING_COUNT]| -f IP_ADDRESS1 -t IP_ADDRESS2 [-n PING_COUNT]')
		sys.exit(2)
	n='2' #By default, try only 2 pings (the first might time-out)
	a_from=''
	a_to=''
	for opt, arg in opts:
		if opt in ['-n','--npings']:
			n=arg
		elif opt in ['-a','--address']:
			print("Pinging", arg,":")
			ping_wrapper(arg,n)
			#TODO: print
			#sys.exit()
		elif opt in ["-f", "--from"]:
			a_from = arg
		elif opt in ["-t", "--to"]:
			a_to = arg
	if (a_from=='') != (a_to==''): #xor
		print("In order to use a range, you need to specify BOTH the 'from' (-f) and 'to' addresses.\n \
		Pinging the specified address.")
		ping_wrapper(a_from+a_to,n) #concatenation of an address with an empty string
	else:
		if a_from!='': # we have from and to address
			live=[]
			radical='.'.join(a_from.split(".")[:3]) # e.g., extracts 192.168.1 from 192.168.1.1
			f=int(a_from.split(".")[3]) # e.g., extracts 50 from 192.168.1.50
			t=int(a_to.split(".")[3])
			for i in range(f,t+1): #1 to t
				print('\tPinging',radical+'.'+str(i))
				if ping_wrapper(radical+'.'+str(i),n):
					print(colored('\t  - Active host found','red'))
					live.append(1)
				else:
					print('\t  - Dead')
					live.append(0)
			print("There are ",colored(sum(live),'red'),"Active machines")
			print("Their IP addresses are ",colored([radical+'.'+str(f+i) for i in range(len(live)) if live[i]==1],'blue'))

if __name__ == "__main__":
	main(sys.argv[1:])

#Possible Improvements by students:
#	- Understand CIDR notation 192.168.1.128/25
#	- Multi-threaded, offer an option (-T?) to specify the number of threads (e.g., -T 10)
#	- Throttle the number of forged packets
#	- Understand A:B, C, D:E, etc.
#	- Add TCP SYN pings
#	- Better displays of outputs (e.g., number of live stations + their list)
#	- Add port scanning?
