#!/usr/bin/env python3
"""
SmartClient.py
Marc-Andre Descoteaux V00847029
CSC 361 Assignment 1
TA #huanwanghuanwang@gmail.com
"""

import sys
import os
import socket
import ssl
import re
import time

crlf = "\r\n"
default_version_num = "HTTP/1.1"

# CREATESOCK 
# open a socket, use SSL to wrap the socket and connect to the web server at port 443
def createSock(domainName, sornos):

	# open socket
	try:
		sket = socket.socket()
		sket.settimeout(15)
		# set port number
		port = 80
		if sornos:
			time.sleep(2)
			# wrap the socket with SSL
			print("Wrapping socket...")
			port = 443
			sket = ssl.wrap_socket(sket)

		# initiate TCP server connection between socket and domain
		print("Establishing connection with", domainName,"at port",port,"...")
		sket.connect((domainName, port))

	except socket.error as socketerror:
		print("Socket could not be opened. Error: ", socketerror, "\nExiting...")
		sys.exit(1)

	print("...Connection successful.\n")

	return sket
# checkHTTPs
# create a new socket wrapped at port 443 to verify HTTPS support
def checkHTTPs(webserver, version, sornos, debug):
	if debug:
		print("\n***inside checkHTTPs***\n")
	print("Checking for HTTPs support...(2 second delay)\n")
	sket = createSock(webserver, True)
	request(sket, webserver, version, debug)
	
	webserver, support, version, sornos, cookies = response(sket, webserver, sornos, True, debug)
	if debug:
		print("Domain:",webserver,"HTTPs Support:", support, version,"https:// found:", sornos, "Cookies List:\n",cookies)
	if not support:
		print("...HTTPs not supported\n")

	if debug:
		print("\n***leaving checkHTTPs***\n")
	return support, version, sornos, cookies, False
	

# REQUEST
# send an HTTP request through the socket
def request(sket, webserver, version, debug):

	# generate HTTP request
	print("Generating request...")
	request_line = "GET / " + version + " "+ crlf
	general_header = "Connection: Keep-Alive" + crlf 
	request_header = "User-Agent: curl/7.35.0" + crlf +"Host: " + webserver + crlf +crlf

	
	request = request_line + request_header
	byte_request = request.encode()

	if debug:
		print("bytestring sent:")
		print(byte_request)

	# send HTTP request through socket
	print("---Request begin---")
	sket.sendall(byte_request)
	print(request)
	print("---Request end---")

# CHECKHEAD 
# parse through the header response received and find the HTTP version and response status code
def checkHead(head, debug):

	if debug:
		print("\n***inside checkHead***\n")

	patt1 = re.compile("HTTP/\d\.\d")
	patt2 = re.compile("\d{3}")

	version = patt1.match(head).group()
	code = patt2.search(head).group()

	if debug:
		print(version)
		print(code)
		print("\n***leaving checkHead***\n")
	
	return version, code

# FINDLINK 
# if status code 3xx, search for the new URL given and send another request
def findLink(response_head, debug):
	
	if debug:
		print("\n***inside findLink***\ndebug:")
		print(response_head)
	
	#patt = re.compile("(Location: http[s]?://)((www.\S+\.\w+)(?!http[s]?://))")
	patt = re.compile("(Location: http[s]?://)((www.\S+\.\w{2,3})(/)?(?!http[s]?://))")
	patt1 = re.compile("https://")
	match = patt.search(response_head).group()
	if patt1.search(match) is not None:
		sornos = True
	else:
		sornos = False
	webserver = patt.search(match).group(3)

	if debug:
		print(webserver)
		print(sornos)
		print("\n***leaving findLink***\n")

	return webserver, sornos

# FINDCOOKIES
def findCookies(response_head, domain, debug):

	if debug:
		print("\n***inside findCookies***\n")

	patt = re.compile("Set-Cookie: .+")
	patt1 = re.compile("(\S+)(=\S*;)")
	patt2 = re.compile("([Dd]omain=)(\S+)")
	# create a list from all lines starting with Set-Cookie from the header response
	cook_found = patt.findall(response_head)
	"""
	if debug:
		print(cook_found)
	"""
	cookies = []
	#find name, keys, and domain name from the list of cookies found
	for cook in cook_found:

		if debug:
			print(cook)

		if patt1.search(cook) is not None:
			key = patt1.search(cook).group(1)

			if debug:
				print("key ", key)

		else:
			key = '-'
		if patt2.search(cook) is not None:
			domain = patt2.search(cook).group(2)

			if debug:
				print(domain)
		# format cookies found for output as answers
		cooky = "name: -, key: "+key+", domain name: "+domain

		if debug:
			print(cooky)

		cookies.append(cooky)
	if debug:
		print("\n***leaving findCookies***\n")
	return cookies

# RESPONSE
def response(sket, webserver, sornos, inCheck, debug):
	# defaults
	support = None
	cookies = None
	domain = webserver
	print("HTTP request sent, awaiting response...")
	# receive response through socket
	byte_response = sket.recv(4096)
	"""
	if debug:
		print("Byte response received:")
		print(byte_response)
	"""
	response = byte_response.decode("utf-8")
	if response is '' or response is None:
		print("No response received. Exiting...")
		sys.exit(1)

	print("...Response received.\n")

	# split the response head and body
	response_list = response.split(crlf+crlf)
	"""
	if debug:
		print(response_list)
	"""
	response_head = response_list[0]
	if len(response_list) > 2:
		response_body = response_list[1]
	else:
		response_body = "No Content\n"

	# find HTTP version and response code
	version, code = checkHead(response_head, debug)

	# change answers based on status code received
	
	if code == '200':
		# if the request came from the branch 302 (sornos = true) or the method checkHTTPs(), HTTPs support is true and the program will print out the answers soon
		if sornos or inCheck:
			support = True
			webserver = None
		#else close the current socket and check for HTTPs support with a socket connected to port 443
		else:
			sket.close()
			support, version, sornos, cookies, inCheck = checkHTTPs(webserver, version, sornos, debug)
			webserver = None
			if support:
				return webserver, support, version, sornos, cookies
	# if code 301 then parse the response header to find the new location and check for HTTPs support
	elif code == '301':
		print("Status "+code+" found.")
		webserver, sornos = findLink(response, debug)
		# if the new URL begins with https:// then the domain supports HTTPs
		if sornos:
			support = True
		# check for HTTPs support at new location
		support, version, sornos, cookies, inCheck = checkHTTPs(webserver, version, sornos, debug)
		webserver = None
		# if HTTPs is supported then return to main with the response from port 443
		if support:
			return webserver, support, version, sornos, cookies
	# if 302, create another request to port 80 with the new URL
	elif code == '302':
		print("Status "+code+" found.")
		webserver, sornos = findLink(response, debug)
		return webserver, support, default_version_num, sornos, cookies;
	# if 400, a bad request was generated so return to main and print out the answers from the response
	elif code == '400':
		print("Bad request")
		webserver = None
	# if 400, no further queries, print out answers according to the response head received
	elif code == '404':
		print("Domain requested not found. Please check the link and try again.")
		webserver = None
	# if 408, request timed out, close the program
	elif code == '408':
		print("Request Timeout. Exiting...")
		sys.exit(1)
	# if 505, HTTP version not supported so return to main and generate a new request with a different version of HTTP
	elif code == '505':
		print("Error 505. HTTP version not supported. Switching to 1.0")
		return webserver, support, "HTTP/1.0", sornos, None
	# else status code can not be handle, end program
	else:
		print("Unrecognized status code. Exiting...")
		sys.exit(1)

	# print the response received
	if inCheck:
		print("From request to port 443")
	elif code == '302':
		print("From request to port 80")
	print("---Response header---")
	print(response_head)
	print("\n---Response body---")
	print(response_body)

	# find cookies received
	cookies = findCookies(response_head, domain, debug)
	
	return webserver, support, version, sornos, cookies

# ANSWERS
# output answers as per problem definition
def answers(domainName, support, version, cookies):

	print("website: "+ domainName)
	if support:
		print("1. Support of HTTPS: yes")
	else:
		print("1. Support of HTTPS: no")
	print("2. The newest HTTP versions that the web server supports: "+version)
	print("3. List of Cookies:")
	for cook in cookies:
		print(cook)

# MAIN
def main():

	debug = False
	# check for debugging argument
	if len(sys.argv) > 2:
		if sys.argv[2] == "--debug":
			debug = True
			print("\n\nIn Debug Mode:\n\n")

	print("Program start...")

	# identify domain name from arguments and init values

	domainName = sys.argv[1]
	webserver = domainName
	version = default_version_num
	sornos = False

	# create socket for connecting to web server
	# send request to web server
	while 1:
		sket = createSock(webserver, sornos)
		request(sket, webserver, version, debug)
		webserver, support, version, sornos, cookies = response(sket, webserver, sornos, False, debug)
		sket.close()
		if webserver is None:
			break
	"""
	version = 
	getHTTP2:
		send http2 request. if status is not 4xx/5xx then version is 2.0
	"""
	# output answers
	answers(domainName, support, version, cookies)

if __name__ == '__main__':
	main()

"""
need to check 2.0 support
Bugs: 
cbc: good
uvic: after sending wrapped sock at 443 -> bad request
google: good
mcgill: inconsistent but mostly good
youtube: good
akamai: good
bc gov: good
python: good
bbc: good
aircanada: no hostname when wrapping sock with full location name after 301 status
			no https cookies if not following through on 301, if follow through 			with checkHTTPs or return: inf loop

"""

