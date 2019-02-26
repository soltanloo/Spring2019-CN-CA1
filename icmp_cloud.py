

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
import random
from impacket import ImpactPacket

# ICMP parameters
ICMP_ECHOREPLY = 0 # Echo reply (per RFC792)
ICMP_ECHO = 8 # Echo request (per RFC792)
ICMP_MAX_RECV = 2048 # Max size of incoming buffer

MAX_SLEEP = 1000

class Client(object):

	def __init__(self, my_ip, num_of_hosts):
		self.my_ip = my_ip
		self.num_of_hosts = num_of_hosts
		self.collected_files = dict()
		self.wanted_files = dict()
		self.our_wanted_files = []
		self.added_files = dict()
		self.connection_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		self.connection_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	def header2dict(self, names, struct_format, data):
		""" unpack the raw received IP and ICMP header informations to a dict """
		unpacked_data = struct.unpack(struct_format, data)
		return dict(zip(names, unpacked_data))

	def generate_src_dst(self):
		src = "10.0.0." + str(random.randint(1, self.num_of_hosts))
		while src == self.my_ip:
			src = "10.0.0." + str(random.randint(1, self.num_of_hosts))
		dst = "10.0.0." + str(random.randint(1, self.num_of_hosts))
		while dst == self.my_ip or src == dst:
			dst = "10.0.0." + str(random.randint(1, self.num_of_hosts))
		return src, dst

	def send_packet(self, mode="send_chunk", chunk_id=None, chunk_data=None, file_name=None, src_ip=None):
		if mode == "send_chunk":
			ip = ImpactPacket.IP()
			src, dst = self.generate_src_dst()
			if src_ip is not None:
				src = src_ip
			ip.set_ip_src(src)
			ip.set_ip_dst(dst)	

			#Create a new ICMP ECHO_REQUEST packet 
			icmp = ImpactPacket.ICMP()
			icmp.set_icmp_type(icmp.ICMP_ECHO)

			#inlude a small payload inside the ICMP packet
			#and have the ip packet contain the ICMP packet
			icmp.contains(ImpactPacket.Data(file_name + "$" + chunk_data))
			ip.contains(icmp)

			#give the ICMP packet some ID
			icmp.set_icmp_id(chunk_id)
			
			#set the ICMP packet checksum
			icmp.set_icmp_cksum(0)
			icmp.auto_checksum = 1

			# send the provided ICMP packet over a 3rd socket
			self.connection_socket.sendto(ip.get_packet(), (dst, 1)) # Port number is irrelevant for ICMP

		elif mode == "return_home":
			ip = ImpactPacket.IP()
			src, dst = self.generate_src_dst()
			ip.set_ip_src(src)
			ip.set_ip_dst(dst)

			#Create a new ICMP ECHO_REQUEST packet 
			icmp = ImpactPacket.ICMP()
			icmp.set_icmp_type(icmp.ICMP_ECHO)

			#inlude a small payload inside the ICMP packet
			#and have the ip packet contain the ICMP packet
			icmp.contains(ImpactPacket.Data("return_home" + "$" + file_name + "$" + self.my_ip))
			ip.contains(icmp)

			#give the ICMP packet some ID
			icmp.set_icmp_id(0x03)
			
			#set the ICMP packet checksum
			icmp.set_icmp_cksum(0)
			icmp.auto_checksum = 1

			# send the provided ICMP packet over a 3rd socket
			self.connection_socket.sendto(ip.get_packet(), (dst, 1)) # Port number is irrelevant for ICMP

	def receive_packet(self):
		packet_data, address = self.connection_socket.recvfrom(ICMP_MAX_RECV)

		icmp_header = self.header2dict(
			names=[
				"type", "code", "checksum",
				"packet_id", "seq_number"
			],
			struct_format="!BBHHH",
			data=packet_data[20:28]
		)

		if icmp_header["type"] == ICMP_ECHOREPLY:
			payload_data = packet_data[28:].split("$")
			if payload_data[0] == "return_home":
				print("return_home packet recieved!, src_ip:", payload_data[2], "file_name:", payload_data[1])
				self.wanted_files[payload_data[1]] = payload_data[2]
			else:
				if payload_data[0] in self.wanted_files:
					self.send_packet(chunk_id=int(icmp_header["packet_id"]),
						chunk_data=payload_data[1], file_name=payload_data[0], src_ip=self.wanted_files[payload_data[0]])

					# print("SENDING reutrn packets!!!\n", "file name:", payload_data[0], "chunk id:", int(icmp_header["packet_id"]), "src ip:", self.wanted_files[payload_data[0]])
				
				elif payload_data[0] in self.added_files and payload_data[0] in self.our_wanted_files:
					self.collect_chunk(payload_data[0], payload_data[1], int(icmp_header["packet_id"]))
				else:
					self.send_packet(chunk_id=int(icmp_header["packet_id"]),
						chunk_data=payload_data[1], file_name=payload_data[0])
			return
		else:
			return

	def split_file(self, file_name, chunk_size=8):
		chunks = []
		f = open(file_name, 'rb')
		chunk = f.read(chunk_size)
		while chunk:
			chunks.append(chunk)
			chunk = f.read(chunk_size)
		return chunks

	def collect_chunk(self, file_name, chunk_data, chunk_id):
		print("collecting chunks, num:", chunk_id, "data:", chunk_data)
		self.collected_files[file_name][chunk_id] = chunk_data
		# print("added_files[file_name] = ", self.added_files[file_name])
		# print("collected_files[file_name].keys() len is :", len(self.collected_files[file_name].keys()))
		if (len(self.collected_files[file_name].keys()) == (self.added_files[file_name] - 15)):
			self.pack_file(file_name, self.collected_files[file_name])
			self.our_wanted_files.remove(self.our_wanted_files.index(file_name))
			del self.added_files[file_name]

	def pack_file(self, file_name, chunks):
		f = open("recovered_" + file_name, "w+")
		for i in range(len(chunks.keys())):
			f.write(chunks[i])
			print(chunks[i])
		f.close()
		print("file recovered :		recoverd_" + file_name)

	def run_server(self):
		while True:
			inputready, outputready, exceptionready = select.select([self.connection_socket, sys.stdin], [], [])
			if sys.stdin in inputready:
				command = sys.stdin.readline().rstrip()
				commandParts = command.split(" ")
				if commandParts[0] == "return_home":
					self.our_wanted_files.append(commandParts[1])
					self.collected_files[commandParts[1]] = dict()
					self.send_packet(mode="return_home", file_name=commandParts[1])
				elif commandParts[0] == "add_file":
					chunks = self.split_file(commandParts[1])
					self.added_files[commandParts[1]] = len(chunks)
					for chunk_id, chunk in enumerate(chunks):
						self.send_packet(chunk_id=chunk_id, chunk_data=chunk, file_name=commandParts[1])
			elif self.connection_socket in inputready:
				self.receive_packet()

if __name__ == "__main__":
		client = Client(sys.argv[1], int(sys.argv[2]))
		client.run_server()