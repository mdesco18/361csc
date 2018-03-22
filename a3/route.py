"""
route.py
Marc-Andre Descoteaux
V00847029
CSC361 Assignment 3
The purpose of this program is to analyze a pcap file generated by a traceroute command and output findings.
"""

import sys
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer3 import icmp
#from pypacker.layer3 import ip_shared as protolist

# global variables
debug = False
packet_num = 0
true_src = 'none'
true_dst = 'none'
inter_node = []
protocols = {}
id_ttl = {}
frags = {}

# convert nanosecond to seconds on timestamps
def nano_to_sec(nans):
	
	return nans / 1000000000
	
def addProto(protocol):

	global protocols
	# only doing a few known/likely protocols for simplicity in this assignment. Thinking of implementing fully with Regex against ip_shared.py
	if protocol == ip.IP_PROTO_ICMP:
		protocols[1] = 'ICMP'
	elif protocol == ip.IP_PROTO_TCP:
		protocols[6] == 'TCP'
	elif protocol == ip.IP_PROTO_UDP:
		protocols[17] == 'UDP'
	else:
		protocols[protocol] == 'Other'
	

#read packets from file and parse IP header
def readPacks(file):
	global debug
	global packet_num
	global true_src
	global true_dst
	global frags
	found = False;
	
	pcap = ppcap.Reader(filename=file)
		
	for ts, buf in pcap:
		packet_num += 1
		eth = ethernet.Ethernet(buf)
		ts = nano_to_sec(ts)
		
		if eth[ip.IP] is not None:
			if debug:
				print("-----------------")
				print("Frame:",packet_num)
				print("%d: %s -> %s" % (ts, eth[ip.IP].src_s, eth[ip.IP].dst_s))
		# get information about packet
			src_ip = eth[ip.IP].src_s
			dst_ip = eth[ip.IP].dst_s
			protocol = eth[ip.IP].p
			ttl = eth[ip.IP].ttl
			id = eth[ip.IP].id
			flags = eth[ip.IP].flags
			head_length = eth[ip.IP].hl
			length = len(buf)
			
			if debug:
				print("source",src_ip)
				print("dest",dst_ip)
				print("proto",protocol)
				print("ttl",ttl)
				print("id",id)
				print("flags",flags)
				print("header",head_length)
				print("length",length)
			
			if not found and (protocol == IP_PROTO_ICMP or protocol == IP_PROTO_UDP) and ttl == 1:
				true_src = src_ip
				true_dst = dst_ip
				found = True
				
			addProto(protocol)
			id_ttl[id] = ttl
			
			if id is not in frags:
				frags[id] = 0
			elif flags == ip.IP_MF:
				frags[id] = frags[id] + 1
			
			if protocol == ip.IP_PROTO_ICMP:
				if debug:
					print("ICMP found")
				type = eth[icmp.ICMP].type
				if type == icmp.ICMP_TIMEXCEED:
					if debug:
						print("TTL exceeded")
					if dst_ip == true_src:
						inter_node.append(src_ip)
						
						#see if i can read the payload and get the ttl or timestamp so i can use a dict instead ^
						#looks like its possible in pypacker.py with upper_layer method
				
def main():

	global debug
	# check for debugging argument
	if len(sys.argv) > 2:
		if sys.argv[2] == "--debug" or sys.argv[2] == "-d":
			debug = True
			print("\nIn Debug Mode:\n")
	if len(sys.argv) > 3:
		sys.stdout = open(str(sys.argv[3]), 'w')
	
	fi = str(sys.argv[1])
	
	if debug:
		print("Program start...")
		print("File:",fi)
		print("Begin reading packets...")
	
	readPacks(fi)
	
	if debug:
		print("All packets read.")
	
	#output()
	

	if sys.argv[2] is not None and sys.argv[2] == "-o":
		sys.stdout.close()

if __name__ == '__main__':
	main()