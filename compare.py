# This is a helper script for comparing PCAP files

from scapy.all import *

def compare_pcaps(pcap1_filepath, pcap2_filepath):

	# Open PCAP files
	pcap1 = rdpcap(pcap1_filepath)
	pcap2 = rdpcap(pcap2_filepath)
	
	# First check
	pcap1_len = len(pcap1)
	pcap2_len = len(pcap2)
	print(pcap1_filepath + ": " + str(pcap1_len) + " packets")
	print(pcap2_filepath + ": " + str(pcap2_len) + " packets")
	if pcap1_len != pcap2_len:
		print("PCAPs not the same!")
		return False
		
	# Check all the packets
	for i in range(0, pcap1_len):
		if pcap1[i] != pcap2[i]:
			print("Mismatch at packet " + str(i + 1) + "!")
			return False
	
	print("All packets contain the same data!")
	return True
	
compare_pcaps("test.pcap", "test_output.pcap")
