package org.eldavojohn.pcap.transport

import groovy.util.logging.Log4j

import org.eldavojohn.pcap.application.BootpEvent
import org.eldavojohn.pcap.application.DnsEvent
import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.events.UdpEvent
import org.eldavojohn.pcap.io.PcapIOUtilities

@Log4j
class UdpHandler {
	static processUdpMessage(byte[] payload, CommunicationEvent ce) {
		
		UdpEvent ue = new UdpEvent()
		ue.sourcePort = Integer.parseInt(PcapIOUtilities.bytesToHex(payload[0..1]), 16)
		ue.destinationPort = Integer.parseInt(PcapIOUtilities.bytesToHex(payload[2..3]), 16)
		ue.length = Long.parseLong(PcapIOUtilities.bytesToHex(payload[4..5]), 16)
		ue.checksum = Long.parseLong(PcapIOUtilities.bytesToHex(payload[6..7]), 16)
		ue.udpMessage = payload[8..(payload.size() - 1)]
		ce.subEvents.add(ue)
	}
}
