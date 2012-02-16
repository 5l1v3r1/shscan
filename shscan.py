import sys
import re
import subprocess
import paramiko
import socket
import time
from threading import Thread
from optparse import OptionParser

# confirm that the host is up; this can be done with a simple
# ping.  Also detect if we're getting ICMP prohibited responses; this means
# we're probably getting denied by a firewall/router or the system is 
# configured to deny icmp echo requests.
def check_host ( addr ):
	try:
		process = subprocess.Popen(['ping', '-c', '2', '-W', '1', addr], 
						stdout = subprocess.PIPE,
						stderr = subprocess.PIPE)
		process.wait()
		line = process.stdout.read().decode("utf-8")
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
		# disabled, for now:
		#ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		w = ssh.connect(ip, port, username='test', 
				password='test', timeout=1.0)
	except paramiko.SSHException, j:
		ssh.close()
		print '[+] SSH found at port %s'%port
		return
	except Exception, e:
		ssh.close()
		return

# simple port scanner for some basic stuff
def port_scan(addr, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
	except Exception:
		sock.close()
		sock = None
		return False

# entry
def main():

	parser = OptionParser()
	parser.add_option("-s", help="Skip host discovery", action="store_true", 
							default=False, dest="skip")
	parser.add_option("-r", metavar="x-y", help="Specify a range of ports", 
					  action="store", dest="p_range" )
	parser.add_option("-i", help="The address to scan",
					  action="store", dest="addr") 
	parser.add_option("-a", help="Scan all 65,535 ports", 
					  action="store_true", default=False, dest="all_ports")
	parser.add_option("-p", help="Do a port scan of the given ports (with -r)",
					  action="store_true", default=False, dest="port_scan")

	(options, args) = parser.parse_args()

	if options.addr is None:
		print 'Use -i to specify an address (-h for help)'
		sys.exit(0)

	# lets see if the host is up
	if options.skip is False:
		print '[+] Checking address \'%s\''%options.addr
		if check_host(options.addr) is False:
			print '[-] No route to host.  Host might be down or dropping probes.'
			print '[-] Trying running with \'-s\' to skip if you know it\'s up.'
			sys.exit(0)
		else:
			print '[+] Host is up.'
	
	# shscan 
	if options.port_scan is False:
		print '[+] Scanning \'%s\''%options.addr 
		if options.p_range is not None:
			(lower, sep, upper) = options.p_range.partition("-")
			for i in range(int(lower),int(upper)):
				thread = Thread(target=shscan, args=(options.addr, i))
				thread.start()
		# scan ALL the ports!
		elif options.all_ports:
			for i in range(65535):
				thread = Thread(target=shscan, args=(options.addr, i))
				thread.start()
		# else scan all the well known ports 
		else:
			for i in range(1023):
				thread = Thread(target=shscan, args=(options.addr, i))
				thread.start()
	
	# port scan.
	# There's a limit to the maximum number of descriptors
	# a system can have open at a time.  The default in ubuntu-based
	# systems is 1024 (ulimit -n).  To mitigate overloading that and
	# crashing and burning, I sleep the loop every 1000 threads to
	# give them time to close before spawning the next batch.
	if options.port_scan is True:
		print '[+] Port scanning \'%s\''%options.addr
		(lower, sep, upper) = options.p_range.partition("-")
		for i in range(int(lower), int(upper)):
			if i%1000 == 0:
				time.sleep(1)
			thread = Thread(target=port_scan, args=(options.addr, i))
			thread.start()

# real entry
if __name__=="__main__":
	main()
