package org.eldavojohn.pcap.events

import groovy.util.logging.Log4j

@Log4j
class CommunicationEvent {
	String srcMacAddress, dstMacAddress, srcIpAddress, srcPort, dstIpAddress, dstPort, etype
	
	String ssidAddress, ssidName
	
	String ipProtocolVersion, protocolType
	
	int ipVersion
	long totalLength, timeToLive
	Date packetBlockTimestamp
	
	def subEvents = new ArrayList<Object>()
	
	byte[] payload
}
