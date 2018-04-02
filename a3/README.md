README.md route.py

Author: Marc-Andre Descoteaux
Student: V00847029 mdesco18@uvic.ca
Project: CSC361 Spring '18 Assignment 3

This program is designed to analyze the IP header information from a pcap file captured during a traceroute

This program uses module pypacker created by mike01.

It can be downloaded and installation instructions can be found here: https://github.com/mike01/pypacker

	Easy Installation: where the pypacker repository is cloned, invoke "python setup.py install" at the command line.

To run:

	invoke "python route.py <pcap_file> -o <outfile.txt>" at the command line
	
	IMPORTANT NOTE: 
		This program will only work with .pcap files and not .pcapng files.
		This is a limitation of the (minor) implementation of pcapng (in pcapng.py) of the pypacker module.

	Additionally:

	"--debug" or "--d" may be used as the 3rd argument instead of -o to print out intermediate object information used for debugging.

	To print to the console, omit <outfile.txt>.

The program will output the following information gathered from the pcap file:
	
	Marking Concerns for TA's:
		1)
		2)

Output Format: 

	The IP address of the source node: <source_ip>
	The IP address of ultimate destination node: <ultimate_ip>
	The IP addresses of the intermediate destination nodes:
		router 1: <intermediate_ip>
		router 2: 
		...
		router n:
	
	The values in the protocol field of IP headers:
		<val>: <protocol>
	
	
	The number of fragments created from the original datagram is: <val>
	
	The offset of the last fragment is: <val>
	
	The avg RRT between <source> and <intermediate> is: <val> ms, the s.d. is: <val> ms
 	The avg RRT between <source> and <ultimate> is: <val> ms, the s.d. is: <val> ms
