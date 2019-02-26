

"""
	A pure python ping implementation using raw sockets.

	Note that ICMP messages can only be send from processes running as root
	
"""


import os
import select
import signal
import struct
import sys
import time
import socket,sys
from impacket import ImpactPacket
import ifaddr

import os
import select
import signal
import struct
import sys
import time
import socket,sys, select
from impacket import ImpactPacket
# import ifaddr
import random

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
READ_WRITE = READ_ONLY | select.POLLOUT


class Ping(object):
	def __init__(self, source, destination, timeout=1000, packet_size=55, own_id=None, quiet_output=False, udp=False, bind=None):
		self.quiet_output = quiet_output
		if quiet_output:
			self.response = Response()
			self.response.destination = destination
			self.response.timeout = timeout
			self.response.packet_size = packet_size

		self.destination = destination
		self.source = source
		self.timeout = timeout
		self.packet_size = packet_size
		self.udp = udp
		self.bind = bind

		if own_id is None:
			self.own_id = os.getpid() & 0xFFFF
		else:
			self.own_id = own_id

		try:
			self.dest_ip = to_ip(self.destination)
			if quiet_output:
				self.response.destination_ip = self.dest_ip
		except socket.gaierror as e:
			self.print_unknown_host(e)
		else:
			self.print_start()

		self.seq_number = 0
		self.send_count = 0
		self.receive_count = 0
		self.min_time = 999999999
		self.max_time = 0.0
		self.total_time = 0.0

	def header2dict(self, names, struct_format, data):
		""" unpack the raw received IP and ICMP header informations to a dict """
		unpacked_data = struct.unpack(struct_format, data)
		return dict(zip(names, unpacked_data))

def create_socket():
	try: 
		current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		current_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		if self.bind:
			print('self.bind: ', self.bind)
			current_socket.bind((self.bind, 0)) # Port number is irrelevant for ICMP

	except socket.error, (errno, msg):
		if errno == 1:
			# Operation not permitted - Add more information to traceback
			#the code should run as administrator
			etype, evalue, etb = sys.exc_info()
			evalue = etype(
				"%s - Note that ICMP messages can only be sent from processes running as root." % evalue
			)
			raise etype, evalue, etb
		raise # raise the original error
	return current_socket

def send_one_ping(ping, current_socket):
		
    #Create a new IP packet and set its source and destination IP addresses
    src = ping.source
    dst = ping.destination
    ip = ImpactPacket.IP()
    ip.set_ip_src(src)
    ip.set_ip_dst(dst)	

    #Create a new ICMP ECHO_REQUEST packet 
    icmp = ImpactPacket.ICMP()
    icmp.set_icmp_type(icmp.ICMP_ECHO)

    #inlude a small payload inside the ICMP packet
    #and have the ip packet contain the ICMP packet
    icmp.contains(ImpactPacket.Data("testData"))
    ip.contains(icmp)


    #give the ICMP packet some ID
    icmp.set_icmp_id(0x03)
    
    #set the ICMP packet checksum
    icmp.set_icmp_cksum(0)
    icmp.auto_checksum = 1

    send_time = default_timer()

    # send the provided ICMP packet over a 3rd socket
    try:
        current_socket.sendto(ip.get_packet(), (dst, 1)) # Port number is irrelevant for ICMP
    except socket.error as e:
        ping.response.output.append("General failure (%s)" % (e.args[1]))
        current_socket.close()
        return

    return send_time

def receive_one_ping(ping, current_socket):
		
    timeout = ping.timeout / 1000.0

    while True: # Loop while waiting for packet or timeout
        select_start = default_timer()
        inputready, outputready, exceptready = select.select([current_socket], [], [], timeout)
        select_duration = (default_timer() - select_start)
        if inputready == []: # timeout
            return None, 0, 0, 0, 0


        packet_data, address = current_socket.recvfrom(ICMP_MAX_RECV)

        icmp_header = ping.header2dict(
            names=[
                "type", "code", "checksum",
                "packet_id", "seq_number"
            ],
            struct_format="!BBHHH",
            data=packet_data[20:28]
        )

        receive_time = default_timer()

        # if icmp_header["packet_id"] == self.own_id: # Our packet!!!
        # it should not be our packet!!!Why?
        if True:
            ip_header = ping.header2dict(
                names=[
                    "version", "type", "length",
                    "id", "flags", "ttl", "protocol",
                    "checksum", "src_ip", "dest_ip"
                ],
                struct_format="!BBHHHBBHII",
                data=packet_data[:20]
            )
            packet_size = len(packet_data) - 28
            ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))
            # XXX: Why not ip = address[0] ???
            return receive_time, packet_size, ip, ip_header, icmp_header

        timeout = timeout - select_duration
        if timeout <= 0:
            return None, 0, 0, 0, 0


def run_server():
	# create socket
	connection_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	connection_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	# select stdin and socket
	while True:
		inputready, outputready, exceptionready = select.select([connection_socket, sys.stdin], [], [])
		if sys.stdin in inputready:
			command = ""
			raw_input(command)
			commandParts = command.split()
			if commandParts[0] == "return_home":

			elif commandParts[0] == "add_file":
				chunks = split_file()
				for chunk in chunks:
					send_packet()
				

		elif connection_socket in inputready:
			receive_packet()


	# stdin --> add file --> send to random 
	# stdin --> return home --> send payload : return_home file ip

	# receive -->

