package org.eldavojohn.pcap.internet

import groovy.util.logging.Log4j

import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.io.PcapIOUtilities
import org.eldavojohn.pcap.transport.TcpHandler
import org.eldavojohn.pcap.transport.UdpHandler

@Log4j
class PcapInternetProtocolVersion4Handler {
	static processIpv4Frame(msg, config, CommunicationEvent ce) {
		def ipversion = (msg[0] >> 4)
		ce.ipVersion = ipversion
		if(ipversion == 4) {
			int IHL = 4*(int )(msg[0] & 0x0F)
			def typeOfService = msg[1]
			int totalLength = Integer.parseInt(PcapIOUtilities.bytesToHex(msg[2..3]), 16)
			ce.totalLength = totalLength
			def protocol = (msg[9] & 0xFF)
			def ttl = (msg[8] & 0xFF)
			ce.timeToLive = ttl
			boolean reserved_flag = msg[9]  & 0b1000
			boolean dont_fragment_flag = msg[9]  & 0b0100
			boolean more_fragments_flag = msg[9]  & 0b0010
			log.info "header checksum " + PcapIOUtilities.bytesToHex(msg[6..7])
			def sourceIpAddress = PcapIOUtilities.bytesToIpAddress(msg[12..15])
			ce.srcIpAddress = sourceIpAddress
			def destinationIpAddress = PcapIOUtilities.bytesToIpAddress(msg[16..19])
			ce.dstIpAddress = destinationIpAddress
			log.info "source IP address " + PcapIOUtilities.bytesToIpAddress(msg[12..15])
			log.info "destination IP address " + PcapIOUtilities.bytesToIpAddress(msg[16..19])
			// TODO get options
			// log.info "Section Options " + PcapBufferHandler.processPacketOptions(msg[20..(IHL - 1)], 0)
			
			def payload = msg[IHL..(msg.size() - 1)]
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
		} else if(ipversion == 6) {
			log.warn "Incorrectly labeled ipv6 in an ipv4 packet!"
		} else {
			log.warn "error parsing some unknown ip protocol: " + ipversion
		}
	}
}
