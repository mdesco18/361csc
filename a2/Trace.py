# Trace.py 
# Author: Marc-Andre Descoteaux V00847029
# Project: CSC361 Project 2
# Description: track TCP trace file state information

import sys
import os
import time
import pcapy as p
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp


debug = False
packet_num = 0
reset = 0
timestamp_begin = {}
prev_ts = {}
timestamp_end = {}
packets_sd = {}
conn_established = {}
conn_complete = []
state_s = {}
state_f = {}
state_r = {}
durations = []
rtt = []
rwin = []

# convert nanosecond to seconds on timestamps
def nano_to_sec(nans):
	
	return nans / 1000000000

# calculate Round Trip Time with the current time stamp and the ACK'd packet's time stamp 
def calcRTT(rconn, ts):
	
	global rtt
	global prev_ts
	
	trip = ts - prev_ts[rconn]
	
	if debug:
		print("Calculating RTT: %s" % ('%.4g' % trip))
		
	rtt.append(trip)

# change timestamps from epoch time to clock dates
def epoch_now(conn):

	global timestamp_begin
	global timestamp_end
	global durations
	
	start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp_begin[conn]))
	end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp_end[conn]))
	duration = timestamp_end[conn]-timestamp_begin[conn]
	durations.append(duration)
	
	if debug: 
		print("Converting Epoch times...\nStart:",start_time,"\nEnd:",end_time,"\nDuration:",duration)
		
	return start_time, end_time
	
	
def readPacks(file):
	global packet_num
	global timestamp_begin
	global timestamp_end
	global conn_established
	global conn_complete
	global reset
	global state_s
	global state_f
	global rwin
	twh = {}
	mtwh = {}
	pcap = ppcap.Reader(filename=file)
	
	for ts, buf in pcap:
		packet_num += 1
		eth = ethernet.Ethernet(buf)
		ts = nano_to_sec(ts)

		if eth[tcp.TCP] is not None:
			if debug:
				print("%d: %s:%s -> %s:%s" % (ts, eth[ip.IP].src_s, eth[tcp.TCP].sport,	eth[ip.IP].dst_s, eth[tcp.TCP].dport))
		#get information about packet
			src_port = eth[tcp.TCP].sport
			dst_port = eth[tcp.TCP].dport
			src_ip = eth[ip.IP].src_s
			dst_ip = eth[ip.IP].dst_s
			src = (src_ip, src_port)
			dst = (dst_ip, dst_port)
			conn = (src, dst)
			rconn = (dst, src)
			seq_num = eth[tcp.TCP].seq
			ack_num = eth[tcp.TCP].ack
			flags = eth[tcp.TCP].flags
			rwin.append(eth[tcp.TCP].win)
			prev_ts[conn] = ts
			
			if debug:
				print("Sequence:",seq_num, "Acknowledgment:", ack_num)
			#create state variables for the connection
			if conn not in state_s:
				state_s[conn] = 0
				packets_sd[conn] = 0
			if conn not in state_f:
				state_f[conn] = 0
			if conn not in state_r:
				state_r[conn] = 0
				
			# if SYN bit is set: mark the start time, start three-way handshake, change state of connection
			if flags == tcp.TH_SYN:
				if debug:
					print("syn")
				timestamp_begin[conn] = ts
				twh[seq_num+1] = seq_num
				state_s[conn] += 1
			
			# if SYN+ACK bits are set: perform second part of three-way handshake, change state of connection, calculate RTT
			elif flags == tcp.TH_SYN+tcp.TH_ACK:
				if debug:
					print("synack")
				if ack_num in twh and twh[ack_num] == ack_num-1:
					del twh[ack_num]
					twh[ack_num] = seq_num+1
					state_s[rconn] += 1
				else:
					if debug:
						print("Waiting for syn+ack to",dst)
				calcRTT(rconn, ts)
				
			# if ACK bit is set: check if three-way handshake needs to be completed and establish connection; if packet is acknowledging a FIN bit, mark connection as completed; if in second part of closing handshake, mark end of time; calculate RTT
			elif flags == tcp.TH_ACK:
				if debug:
					print("ack")
				if seq_num in twh and twh[seq_num] == ack_num:
					if debug:
						print("Connection Established")
					del twh[seq_num]
					conn_established[src] = dst
				if state_f[rconn] == 1:
					conn_complete.append(rconn)
				if state_f[conn] == 2:
					timestamp_end[conn] = ts
				calcRTT(rconn, ts)
			
			# if RST bit is set: increment total number of resets, change state of connection
			elif flags == tcp.TH_RST + tcp.TH_ACK:
				if debug:
					print("rst")
				reset += 1
				state_r[conn] += 1
			
			# if FIN+ACK bit is set: begin the closing handshake; or, continue the second part of the closing handshake; change state of connection
			elif flags == tcp.TH_FIN+tcp.TH_ACK:
				if debug:
					print("fin")
				if ack_num not in mtwh:
					mtwh[ack_num] = seq_num+1
					state_f[conn] += 1
				elif seq_num in mtwh and mtwh[seq_num] == ack_num:
					state_f[rconn] += 1
					del mtwh[seq_num]
					
			# else some other flags were set
			else:
				if debug:
					print("other flags")
			
			# if packet did not have a RST bit, increment number of packets sent
			if conn in state_r and state_r[conn] == 0:
				packets_sd[conn] += 1
			
				if debug:
					print("Packet number:",packet_num,"Packets for",conn, packets_sd[conn])
					print("---------------------------------------------------------------")
			
			
			
def main():
	global debug
	# check for debugging argument
	if len(sys.argv) > 2:
		if sys.argv[2] == "--debug" or sys.argv[2] == "--d":
			debug = True
			print("\nIn Debug Mode:\n")
	if len(sys.argv) > 3:
		sys.stdout = open(str(sys.argv[3]), 'w')

	print("Program start...")
	
	fi = str(sys.argv[1])
	
	if debug:
		print("File:",fi)
		print("Begin reading packets...")
	
	readPacks(fi)
	
	if debug:
		print("All packets read.")
	
	#output partA
	#output partB
	#output partC
	#output partD
	
	if sys.argv[2] is not None and sys.argv[2] == "-o":
		close(str(sys.argv[3]))
	
if __name__ == '__main__':
	main()
