Trace.py Changelog

2018-03-27

- Line 263: 
		 if state_f[rconn] > 0 or state_f[conn] > 0:
			timestamp_end[conn] = ts
			timestamp_end[rconn] = ts
		 
		 changed to 
		 
		if (rconn in state_f and state_f[rconn] > 0) or (conn in state_f and state_f[conn] > 0):
			timestamp_end[rconn] = ts
			timestamp_end[conn] = ts
		
		KeyError from demo occurred because ACK segment was the first packet captured and state_f[rconn] was not yet initialized.
		
2018-02-13

- Added relative_time function so that to get start time, end time and duration in part B, relative_time is used now instead of epoch_now
- The state of reset for a connection will remain at 1 for each subsequent reset, instead of increasing
- README.md updated to remove "Marking Concerns" 

2018-02-08

- Commit Log:
	 Added methods for formatting and outputting the data. Project finished

2018-02-07

- added descriptive commenting and cleaned up debugging statements

2018-02-06

- Dropped pcapy module in favor of mike01's pyparser module
- Commit Log:  
	Trace.py completely redesigned: 
	now using mike01's pyparser module;
	added methods for reading and parsing packets,
	designating other methods depending on the flags; 
	added methods for time conversions/calculating timestamps; 
	changed readme.md to reflect code, arguments and output

2018-02-05

- Project Start