package org.eldavojohn.pcap.application

import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.events.UdpEvent
import org.eldavojohn.pcap.io.PcapIOUtilities

class DnsProcessor {
	static processEvent(event) {
		// TODO domain name wildcarding aliasing in multi requests
		DnsEvent de = new DnsEvent()
		if(event.getClass() == TcpEvent.class) {
			TcpEvent tcpEvent = (TcpEvent )event
			if(tcpEvent['tcpMessage']) {
				de.dnsId = tcpEvent.tcpMessage[0..1]
				de.flagsAndCodes = tcpEvent.tcpMessage[2..3]
				de.questionCount = Integer.parseInt(PcapIOUtilities.bytesToHex(tcpEvent.tcpMessage[4..5]), 16)
				de.answerCount = Integer.parseInt(PcapIOUtilities.bytesToHex(tcpEvent.tcpMessage[6..7]), 16)
				de.nameServerCount = Integer.parseInt(PcapIOUtilities.bytesToHex(tcpEvent.tcpMessage[8..9]), 16)
				de.additionalCount = Integer.parseInt(PcapIOUtilities.bytesToHex(tcpEvent.tcpMessage[10..11]), 16)
				if(tcpEvent.tcpMessage.size() > 12) {
					de.queryDomains.add(PcapIOUtilities.byteArrayToDnsReadableWithDots(tcpEvent.tcpMessage[12..(tcpEvent.tcpMessage.size() - 1)]))
				}
			}
			return de
			// println insp
		} else if (event.getClass() == UdpEvent.class) {
			UdpEvent udpEvent = (UdpEvent )event
			if(udpEvent['udpMessage']) {
				de.dnsId = udpEvent.udpMessage[0..1]
				de.flagsAndCodes = udpEvent.udpMessage[2..3]
				de.questionCount = Integer.parseInt(PcapIOUtilities.bytesToHex(udpEvent.udpMessage[4..5]), 16)
				de.answerCount = Integer.parseInt(PcapIOUtilities.bytesToHex(udpEvent.udpMessage[6..7]), 16)
				de.nameServerCount = Integer.parseInt(PcapIOUtilities.bytesToHex(udpEvent.udpMessage[8..9]), 16)
				de.additionalCount = Integer.parseInt(PcapIOUtilities.bytesToHex(udpEvent.udpMessage[10..11]), 16)
				if(udpEvent.udpMessage.size() > 12) {
					de.queryDomains.add(PcapIOUtilities.byteArrayToDnsReadableWithDots(udpEvent.udpMessage[12..(udpEvent.udpMessage.size() - 1)]))
				}
			}
			return de
		}
	}

}
