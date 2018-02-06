ReadMe.txt

This is the ReadMe file for the program SmartClient.py written by Marc-Andre Descoteaux - V00847029 for CSC 361 UVic Spring 2018

To run the program, open terminal and navigate to the proper directory.

On the command line, invoke: python3 SmartClient.py <url>

<url> is of the form: www.<DomainName>.(com | ca)

To check for HTTP/2.0 support, invoke python3 SmartClient.py <url> --http2

This will call a method that wraps a socket and does a handshake with ALPN protocol set to 'HTTP/2.0'

This method is not tested on the linux.csc as Python 3.5+ is required.

The argument '--http2' exists such that if the method fails, HTTPs support and cookies may still be found. 

an argument "--debug" may be used as the 3rd argument (after <url>) to print out intermediary debugging to the console

*Special Cases with concerns for marking*

1) attempting to access www.uvic.ca with port 443 results in a 400 Bad Request error

2) http://www.mcgill.ca does not always redirect to https://www.mcgill.ca resulting in inconsistency when checking for HTTPs support

3) www.aircanada.com will always attempt to redirect to www.aircanada.com/ca/en/aco/home.html and an HTTP request to that URI becomes impossible

