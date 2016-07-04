package org.eldavojohn.pcap.internet

import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.io.PcapIOUtilities
import org.eldavojohn.pcap.transport.TcpHandler
import org.eldavojohn.pcap.transport.UdpHandler

import groovy.util.logging.Log4j

@Log4j
class PcapInternetProtocolVersion6Handler {

	static processIpv6Frame(msg, config, CommunicationEvent ce) {
		def ipversion = (msg[0] >> 4)
		int totalLength = Integer.parseInt(PcapIOUtilities.bytesToHex(msg[4..5]), 16)
		log.info "Processing frame of ip version " + ipversion
		String sourceAddress = PcapIOUtilities.bytesToIpv6Address(msg[8..23])
		ce.srcIpAddress = sourceAddress
		String destinationAddress = PcapIOUtilities.bytesToIpv6Address(msg[24..39])
		ce.dstIpAddress = destinationAddress
		
		assert(msg.size() == totalLength + 40)
		// println "$sourceAddress -> $destinationAddress"
		def protocol = (msg[6] & 0xFF)
		def payload = msg[40..(msg.size() - 1)]
		if(ipversion == 6) {
			if(protocol == 6 && config.pcap.modules.tcp) {
				if(msg.size() < totalLength) {
					// log.warn "how frequently does this happen? " + msg.size() + " != " + totalLength
				}
				ce.protocolType = "tcp"
				TcpHandler.processTcpMessage(payload as byte[], ce)
				
			} else if(protocol == 17 && config.pcap.modules.udp) {
				ce.protocolType = "udp"
				UdpHandler.processUdpMessage(payload as byte[], ce)
			} 
		} else if(ipversion == 4) {
			log.warn "Incorrectly labeled ipv4 in an ipv6 packet!"
		} else {
			log.warn "error parsing some unknown ip protocol: " + ipversion
		}
	}
}
