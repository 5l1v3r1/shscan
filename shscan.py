#!/usr/bin/python

import sys
import re
import subprocess
import paramiko
import socket
import time
from threading import Thread
from optparse import OptionParser

# global debug flag
DEBUG_FLAG = False

# confirm that the host is up; this can be done with a simple
# ping.  Also detect if we're getting ICMP prohibited responses; this means
# we're probably getting denied by a firewall/router or the system is 
# configured to deny icmp echo requests.
def check_host ( addr ):
	global DEBUG_FLAG
	try:
		process = subprocess.Popen(['ping', '-c', '2', '-W', '1', addr], 
						stdout = subprocess.PIPE,
						stderr = subprocess.PIPE)
		process.wait()
		line = process.stdout.read().decode("utf-8")
		if DEBUG_FLAG: print "[dbg] Host returned: \n%s"%line
		up = re.search("\d.*? received", line)
		proh = re.search("Host Prohibited", line)
		if proh:
			print '[-] Host actively prohibiting our pings, but active.'
			return True
		# check if 0 is anywhere in the transmit return string, ergo:
		# 2 packets transmitted, 2 received
		if re.search("0", up.group(0)) is None:
			return True
		else:
			return False
	except Exception:
		return False

# look for shells returned to us and dish out some fake creds.
# This is loud, but it's also more accurate than fingerprinting TCP packets.
def shscan(ip, port):
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		w = ssh.connect(ip, port, username='test', 
				password='test', timeout=1.0)
		ssh.close()
	except paramiko.AuthenticationException, j:
		ssh.close()
		print '[+] SSH found at port %s'%port
		return
	except Exception, e:
		ssh.close()
		return

# simple port scanner for some basic stuff
def port_scan(addr, port):
	global DEBUG_FLAG
	sock = socket.socket()
	sock.settimeout(1.0)
	try:
		sock.connect((addr, port))
		print '[+] Open port at %s'%port
		sock.close()
		sock = None
		return True
	except socket.error, e:
		sock.close()
		sock = None
		return False
	except Exception, j:
		sock.close()
		sock = None
		return False

# get the systems thread limit.
# This is calculated by total RAM / ulimit -s
# Systems generally have different settings for thread caps
# both with totals and per process.  So instead of hard coding
# a default, just automatically calculate and return a thread max.
# There's also now a command for manually setting the thread count.
def thread_limit():
	global DEBUG_FLAG
	try:
		proc = subprocess.Popen(['ulimit -s'], shell=True, 
										stdout = subprocess.PIPE,
										stderr = subprocess.PIPE) 
		total_t = int((proc.stdout.read().decode("utf-8")))/1024

		proc = subprocess.Popen(['free | grep Mem | awk \'{print $2}\''],
								shell=True,
								stdout = subprocess.PIPE,
								stderr = subprocess.PIPE)

		total_mem = int(proc.stdout.read().decode("utf-8"))
		MAX = int(total_mem/1024) / total_t
		if DEBUG_FLAG:
			print '[dbg] Mem: %d'%int(total_mem/1024)
			print '[dbg] Threads: %d'%int(total_t)
			print '[dbg] Net max threads: %d'%MAX
		return MAX 
	except Exception, j:
		print '[-] Couldn\'t get thread max: \'%s\''%j
		return

# entry
def main():
	global DEBUG_FLAG

	parser = OptionParser(epilog=
					"The default scan searches only the first 1023 ports.")
	parser.add_option("-s", help="Skip host discovery", action="store_true", 
							default=False, dest="skip")
	parser.add_option("-r", metavar="x-y", help="Specify a range of ports, " 
					"or give it a single port",  action="store", dest="p_range" )
	parser.add_option("-i", help="The address to scan",
					  action="store", dest="addr") 
	parser.add_option("-a", help="Scan all 65,535 ports", 
					  action="store_true", default=False, dest="all_ports")
	parser.add_option("-p", help="Do a port scan of the given ports",
					  action="store_true", default=False, dest="port_scan")
	parser.add_option("-v", help="Verbose output with debug",
					  action="store_true", default=False, dest="verbose")
	parser.add_option("-t", help="Manually set thread count", dest="threads",
					  action="store" )

	# parse options, set global debug flag
	(options, args) = parser.parse_args()
	DEBUG_FLAG = options.verbose

	# set thread max
	if options.threads is not None:
		THREAD_MAX = int(options.threads)
	else:
		THREAD_MAX = thread_limit()
	
	if DEBUG_FLAG:
		print '[dbg] Using %d threads'%THREAD_MAX

	# ditch if they didn't give us an addr
	if options.addr is None:
		print 'Use -i to specify an address (-h for help)'
		sys.exit(0)
	
	# lets see if the host is up
	if options.skip is False:
		print '[+] Checking address \'%s\''%options.addr
		if check_host(options.addr) is False:
			print '[-] No route to host. Host might be down or dropping probes.'
			print '[-] Trying running with \'-s\' to skip if you know it\'s up.'
			sys.exit(0)
		else:
			print '[+] Host is up.'
	
	# shscan
	# Sleep the loop if we max out current threads, allowing them
	# time to close up
	if options.port_scan is False:
		print '[+] Scanning \'%s\''%options.addr 
		try:
			if options.p_range is not None:
				# if the - is not found, it's a single port
				if not "-" in options.p_range:
					shscan(options.addr, int(options.p_range))
					sys.exit(0)
				(lower, sep, upper) = options.p_range.partition("-")
				for i in range(int(lower),int(upper)):
					if i%THREAD_MAX == 0:
						time.sleep(1)
					thread = Thread(target=shscan, args=(options.addr, i))
					thread.start()
			# scan ALL the ports!
			elif options.all_ports:
				for i in range(65535):
					if i%THREAD_MAX == 0:
						time.sleep(1)
					thread = Thread(target=shscan, args=(options.addr, i))
					thread.start()
			# else scan all the well known ports 
			else:
				for i in range(1023):
					if i%THREAD_MAX == 0:
						time.sleep(1)
					thread = Thread(target=shscan, args=(options.addr, i))
					thread.start()
		except Exception, j:
			print '[-] %s'%j
	
	# port scan.
	if options.port_scan is True:
		print '[+] Port scanning \'%s\''%options.addr
		# scan the given range
		if options.p_range is not None:
			# or the single port
			if not '-' in options.p_range:
				port_scan(options.addr, int(options.p_range))
				sys.exit(0)
			(lower, sep, upper) = options.p_range.partition("-")
			for i in range(int(lower), int(upper)):
				if i%THREAD_MAX == 0:
					time.sleep(2)
				thread = Thread(target=port_scan, args=(options.addr, i))
				thread.start()
		# scan only the top 1023 ports
		else:
			for i in range(1023):
				if i%THREAD_MAX == 0:
					time.sleep(2)
				thread = Thread(target=port_scan, args=(options.addr, i))
				thread.start()

# real entry
if __name__=="__main__":
	main()
