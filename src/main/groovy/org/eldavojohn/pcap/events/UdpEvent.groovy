package org.eldavojohn.pcap.events

class UdpEvent {
	int sourcePort, destinationPort
	long length, checksum
	byte[] udpMessage
	def subEvents = new ArrayList<Object>()
}
