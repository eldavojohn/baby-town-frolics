package org.eldavojohn.pcap.application

import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.events.UdpEvent
import org.eldavojohn.pcap.io.PcapIOUtilities

class BootpProcessor {
	static processEvent(event) {
		if(event.getClass() == TcpEvent.class) {
			TcpEvent tcpEvent = (TcpEvent )event
			BootpEvent bpe = new BootpEvent()
			bpe.bootpName = PcapIOUtilities.byteArrayToRaw(tcpEvent.udpMessage[16..(tcpEvent.udpMessage.size() - 1)])
			return bpe
		} else if (event.getClass() == UdpEvent.class) {
			UdpEvent udpEvent = (UdpEvent )event
			BootpEvent bpe = new BootpEvent()
			bpe.bootpName = PcapIOUtilities.byteArrayToRaw(udpEvent.udpMessage[16..(udpEvent.udpMessage.size() - 1)])
			return bpe
		}
	}
}