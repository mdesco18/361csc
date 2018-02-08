README Trace.py

Author: Marc-Andre Descoteaux
Project: CSC361 P2
Student: V00847029 mdesco18@uvic.ca

This python program is designed to parse and track the TCP states from a packet capture file

This program uses module pypacker created by mike01.

It can be downloaded and installation instructions can be found here: https://github.com/mike01/pypacker

Easy Installation: where the pypacker repo is cloned, invoke "python setup.py install" at the command line

To run:

invoke "python Trace.py <pcap_file> -o <outfile.txt>" at the command line

Additionally:

"--debug" or "--d" may be used as the 3rd argument instead of -o to print out intermediate object information used for debugging

To print to the console, omit <outfile.txt>

The program will output the following information gathered from the pcap file:

	Note: All numerical values will be output with 4 decimal points. 
	To change this, in method 'output()', replace '%0.4" % ' with ':",' from the print statements in part D 
	
	Marking concerns: 
		Part A) 
		Part B) 
		Part C)
			Number of reset TCP connections: 
			is this the number of times the RST bit was parsed or 
			the number of distinct connections that were reset once?
			During testing, at least one of the same connection was 
			shown to have RST more than once. The current program outputs the number of RST bits received.
		Part D)

Output Format:

A) Total number of connections:
B) Connections' details:
Connection 1:
Source Address:
Destination address:
Source Port:
Destination Port:
Status:
(Only if the connection is complete provide the following information)
Start time:
End Time:
Duration:
Number of packets sent from Source to Destination:
Number of packets sent from Destination to Source:
Total number of packets:
Number of data bytes sent from Source to Destination:
Number of data bytes sent from Destination to Source:
Total number of data bytes:
END
+++++++++++++++++++++++++++++++++
.
.
.
+++++++++++++++++++++++++++++++++
Connection N:
Source Address:
Destination address:
Source Port:
Destination Port:
Status:
Duration:
(Only if the connection is complete provide the following information)
Start time:
End Time:
Number of packets sent from Source to Destination:
Number of packets sent from Destination to Source:
Total number of packets:
Number of data bytes sent from Source to Destination:
Number of data bytes sent from Destination to Source:
Total number of data bytes:
END
C) General
Total number of complete TCP connections:
Number of reset TCP connections:
Number of TCP connections that were still open when the trace capture ended:

D) 
Complete TCP connections:
Minimum time durations:
Mean time durations:
Maximum time durations:
Minimum RTT values including both send/received:
Mean RTT values including both send/received:
Maximum RTT values including both send/received:
Minimum number of packets including both send/received:
Mean number of packets including both send/received:
Maximum number of packets including both send/received:
Minimum receive window sizes including both send/received:
Mean receive window sizes including both send/received:
Maximum receive window sizes including both send/received:
