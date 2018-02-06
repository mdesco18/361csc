README Trace.py

Author: Marc-Andre Descoteaux
Project: CSC361 P2
Student: V00847029 mdesco18@uvic.ca

This python program is desgined to parse and track the TCP states from a packet capture file using pcapy.

To run:

invoke "python Trace.py <pcap_file>"

Additionally:

"--debug" or "--d" may be used as the 3rd argument to print out intermediary object information used for debugging.

The program will output the following information gathered from the pcap file:

A) Total number of connections:
B) Connections' details:
Connection 1:
Source Address:
Destination address:
Source Port:
Destination Port:
Status:
(Only if the connection is complete provide the following information)
Start 
time:
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
