#    Copyright (C) 2021 Hani Ragab Hassen

#    This file is part of The HackInABashShell Tools.

#    HackInABashShell is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation version 3 of the License.

#    HackInABashShell is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License along with HackInABashShell. If not, see <https://www.gnu.org/licenses/>.

import sys
def ipv4ToDecimal(ip_str):
	ip=[int(p) for p in ip_str.split('.')]
	print(ip)
	return (ip[0]<<24) + (ip[1]<<16) + (ip[2]<<8) + ip[3]

def ipv4ToHexadecimal(ip_str):
	return hex(ipv4ToDecimal(ip_str))

def main(args):
	print(ipv4ToDecimal(args[0]))
	print(ipv4ToHexadecimal(args[0]))

if __name__ == "__main__":
	main(sys.argv[1:])

# ToDo
# - Add support for URLs
# - Add support for IPv6

