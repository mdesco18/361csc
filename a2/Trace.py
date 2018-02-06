# Trace.py 
# Author: Marc-Andre Descoteaux V00847029
# Project: CSC361 Project 2
# Description: track TCP trace file state information

import sys
import os
import pcapy as p
"""
import impacket.ImpactDecoder as ImpactDecoder
import impacket.ImpactPacket as ImpactPacket
"""

debug = False

def getHead(pack):
	epoch_time = pack.getts()
	time_elapsed = epoch_time[1]/1000000
	epoch_time = epoch_time[0]
	caplen = pack.getcaplen()
	totlen = pack.getlen()
	if debug:
		print("Epoch Time:",epoch_time)
		print("Time elapsed:",time_elapsed)
		print("Caplen:",caplen)
		print("totlen:",totlen)
	
	return epoch_time, time_elapsed, caplen, totlen
	
def main():
	global debug
	# check for debugging argument
	if len(sys.argv) > 2:
		if sys.argv[2] == "--debug":
			debug = True
			print("\n\nIn Debug Mode:\n\n")

	print("Program start...")
	fi = str(sys.argv[1])
	
	if debug:
		print("File:",fi)
		
	reader = p.open_offline(fi)
	#toRead = 1
	print("Attempting to read captured packets")
	#while toRead != 0:
	try:
		pack = reader.next()
		head= pack[0]
		data= pack[1]
	except EOFError:
		toRead = 0
		print("Reading done.")
	if debug:
		print(head)
		print(data)
	
	epoch_time, time_elapsed, caplen, totlen = getHead(head)
	net = reader.getnet()
	mask = reader.getmask()
	if debug:
		print(net)
		print(mask)
	

	
if __name__ == '__main__':
	main()