package org.eldavojohn.pcap.link

import groovy.util.logging.Log4j

import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.internet.PcapInternetProtocolVersion4Handler
import org.eldavojohn.pcap.internet.PcapInternetProtocolVersion6Handler
import org.eldavojohn.pcap.io.PcapIOUtilities

@Log4j
class Ethernet2Handler {
	static processLayer2(payload, config, CommunicationEvent ce) {
		ce.dstMacAddress = PcapIOUtilities.bytesToHex(payload[0..5])
		ce.srcMacAddress = PcapIOUtilities.bytesToHex(payload[6..11])
		def etype = PcapIOUtilities.bytesToHex(payload[12..13])
		ce.etype = etype
		// log.info "ether type " + etype
		// log.info "CRC checksum " + PcapIOUtilities.bytesToHex(payload[(payload.size() - 2)..(payload.size() - 1)])
		if(etype == "0806") {
			// TODO handle ARP
			ce.ipProtocolVersion = "ARP"
			log.info "ARPING"
		} else if(etype == "0800"){
			ce.ipProtocolVersion = "IPv4"
			PcapInternetProtocolVersion4Handler.processIpv4Frame(payload[14..(payload.size() - 1)], config, ce)
		} else if(etype == "86DD"){
			ce.ipProtocolVersion = "IPv6"
			PcapInternetProtocolVersion6Handler.processIpv6Frame(payload[14..(payload.size() - 1)], config, ce)
		} else if(etype == "0105") {
			// TODO what kind of ethertype is this?
			println "105 hit"
		} else {
			log.info "Could not discern ethertype of $etype"
		}
	}
}