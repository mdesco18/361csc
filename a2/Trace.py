# Trace.py 
# Author: Marc-Andre Descoteaux V00847029
# Project: CSC361 Project 2
# Description: track TCP trace file state information

import sys
import os
import time
#import pcapy as p
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

# declaration of global variables
debug = False
reset = 0
timestamp_begin = {}
prev_ts = {}
timestamp_end = {}
packets_sd = {}
conn_established = []
conn_complete = []
state_s = {}
state_f = {}
state_r = {}
durations = []
rtt = {}
rwin = {}
bytes = {}

# convert nanosecond to seconds on timestamps
def nano_to_sec(nans):
	
	return nans / 1000000000

# calculate Round Trip Time with the current time stamp and the ACK'd packet's time stamp 
def calcRTT(conn, ts):
	
	global rtt
	global prev_ts
	
	trip = ts - prev_ts[conn]
	
	if debug:
		print("Calculating RTT: %s" % ('%.4g' % trip))
	
	if conn in rtt:
		rtt[conn].append(trip)
	else:
		rtt[conn] = [trip]

# update receive windows dictionary
def windows(conn, win):

	global rwin
	
	if conn in rwin:
		rwin[conn].append(win)
	else:
		rwin[conn] = [win]
		
# change timestamps from epoch time to clock dates
def epoch_now(conn):

	global timestamp_begin
	global timestamp_end
	global durations
	start_time = time.strftime('%b %d %Y %I:%M:%S %p', time.localtime(timestamp_begin[conn]))
	end_time = time.strftime('%b %d %Y %I:%M:%S %p', time.localtime(timestamp_end[conn]))
	duration = timestamp_end[conn]-timestamp_begin[conn]
	durations.append(duration)
	
	if debug: 
		print("Converting Epoch times...\nStart:",start_time,"\nEnd:",end_time,"\nDuration:",duration)
		
	return start_time, end_time, duration
	
def output():
	global packet_num
	global conn_established
	global conn_complete
	global reset
	global state_s
	global state_f
	global durations
	global rtt
	global rwin
	global bytes
	i = 1
	packs_sr = {}
	
	#part A
	print("A) Total number of connections:", len(conn_established))
	#part B
	print("B) Connections' details:")
	if debug:
		for conn in conn_complete:
			print(conn)
	
	for conn in conn_established:
		rconn = (conn[2], conn[3], conn[0], conn[1])
		print("Connection %d:" % i)
		print("Source Address:", conn[0])
		print("Destination Address:", conn[2])
		print("Source Port:", conn[1])
		print("Destination Port:", conn[3])
		print("Status: S%dF%d R%d" % (state_s[conn], state_f[conn], state_r[conn]))
		if conn in conn_complete:
			start_time, end_time, duration = epoch_now(conn)
			print("Start Time:", start_time, "GMT-08:00")
			print("End_Time:", end_time, "GMT-08:00")
			print("Duration: %.04f seconds" % duration)
			print("Number of packets sent from Source to Destination:", packets_sd[conn])
			print("Number of packets sent from Destination to Source:", packets_sd[rconn])
			tot_packs = packets_sd[conn]+packets_sd[rconn]
			packs_sr[conn] = tot_packs
			print("Total number of packets: %d" % tot_packs)
			print("Number of data bytes sent from Source to Destination:", bytes[conn])
			print("Number of data bytes sent from Destination to Source:", bytes[rconn])
			tot_bytes = bytes[conn]+bytes[rconn]
			print("Total number of data bytes:", tot_bytes)
		print("END")
		print("--------------------------------------------------")		
		i += 1
	#part C
	print("C) General")
	print("Total number of complete TCP connections:", len(conn_complete))
	print("Number of reset TCP connections: %d" % reset)
	open = len(conn_established)-len(conn_complete)
	print("Number of TCP connections that were still open when the trace capture ended:", open)
	#part D
	print("\nD) Complete TCP connections:", len(conn_complete))
	durations.sort()
	
	print("Minimum time durations: %.04f" % durations[0])
	print("Mean time durations: %.04f" % (sum(durations)/len(durations)))
	print("Maximum time durations: %.04f" % durations[-1])
	trips = []
	for conn in rtt:
		if conn in conn_complete:
			trips.extend(rtt[conn])
	trips.sort()
	print("Minimum RTT values including both send/received: %f" % trips[0])
	print("Mean RTT values including both send/received: %.04f" % (sum(trips)/len(trips)))
	print("Maximum RTT values including both send/received: %.04f" % trips[-1])
	packs = list(packs_sr.values())
	packs.sort()
	print("Minimum number of packets including both send/received:", packs[0])
	print("Mean number of packets including both send/received:", sum(packs)/len(packs))
	print("Maximum number of packets including both send/received:", packs[-1])
	windows = []
	for conn in rwin:
		if conn in conn_complete:
			windows.extend(rwin[conn])
	windows.sort()
	print("Minimum receive window sizes including both send/received: %.04f" % windows[0])
	print("Mean receive window sizes including both send/received: %.04f" % (sum(windows)/len(windows)))
	print("Maximum receive window sizes including both send/received: %.04f" % windows[-1])
	

# read packets from pcap file and parse for TCP header information
def readPacks(file):
	packet_num = 0
	global timestamp_begin
	global timestamp_end
	global conn_established
	global conn_complete
	global reset
	global state_s
	global state_f
	global bytes
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
		# get information about packet
			src_port = eth[tcp.TCP].sport
			dst_port = eth[tcp.TCP].dport
			src_ip = eth[ip.IP].src_s
			dst_ip = eth[ip.IP].dst_s
			src = (src_ip, src_port)
			dst = (dst_ip, dst_port)
			conn = (src_ip, src_port, dst_ip, dst_port)
			rconn = (dst_ip, dst_port, src_ip, src_port)
			seq_num = eth[tcp.TCP].seq
			ack_num = eth[tcp.TCP].ack
			flags = eth[tcp.TCP].flags
			winr = eth[tcp.TCP].win
			byte = len(buf)
			windows(conn, winr)
			prev_ts[conn] = ts
			
			if debug:
				print("Sequence:",seq_num, "Acknowledgment:", ack_num)
			#create state variables for the connection
			if conn not in state_s:
				state_s[conn] = 0
			if conn not in packets_sd:
				packets_sd[conn] = 0
			if conn not in bytes:
				bytes[conn] = 0
			if conn not in state_f:
				state_f[conn] = 0
			if conn not in state_r:
				state_r[conn] = 0
			
			packets_sd[conn] += 1
			bytes[conn] += byte
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
					conn_established.append(conn)
				if state_f[rconn] > 0 or state_f[conn] > 0:
					timestamp_end[conn] = ts
					timestamp_end[rconn] = ts
				if conn in conn_established:
					calcRTT(conn, ts)
				elif rconn in conn_established:
					calcRTT(rconn, ts)
			
			# if RST bit is set: increment total number of resets, change state of connection
			elif flags == tcp.TH_RST + tcp.TH_ACK:
				if debug:
					print("rst")
				#if state_r[conn] == 0:
				reset += 1
				state_r[conn] += 1
			
			# if FIN+ACK bit is set: begin the closing handshake; or, continue the second part of the closing handshake; change state of connection
			elif flags == tcp.TH_FIN+tcp.TH_ACK:
				if debug:
					print("fin")
				if ack_num not in mtwh:
					mtwh[ack_num] = seq_num+1
					
					if conn in conn_established and state_f[conn] == 0:
						conn_complete.append(conn)
						timestamp_end[conn] = ts
						state_f[conn] += 1
					elif rconn in conn_established and state_f[rconn] == 0:
						conn_complete.append(rconn)
						timestamp_end[rconn] = ts
						state_f[rconn] += 1
				elif seq_num in mtwh and mtwh[seq_num] == ack_num or state_f[rconn] > 1:
					state_f[rconn] += 1
					del mtwh[seq_num]
				
			# else some other flags were set
			else:
				if debug:
					print("other flags")
				calcRTT(conn, ts)
			
			
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
	
	fi = str(sys.argv[1])
	
	if debug:
		print("Program start...")
		print("File:",fi)
		print("Begin reading packets...")
	
	readPacks(fi)
	
	if debug:
		print("All packets read.")
	
	output()
	

	if sys.argv[2] is not None and sys.argv[2] == "-o":
		sys.stdout.close()
	
if __name__ == '__main__':
	main()
