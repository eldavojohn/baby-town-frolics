package org.eldavojohn.pcap.application

import java.util.stream.Nodes.SizedCollectorTask

import org.eldavojohn.pcap.PcapConstants
import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.events.UdpEvent
import org.eldavojohn.pcap.io.PcapIOUtilities

class BootpProcessor {
	static processEvent(event) {
		if(event.getClass() == TcpEvent.class) {
			TcpEvent tcpEvent = (TcpEvent )event
			return processBootPMessage(tcpEvent.tcpMessage)
		} else if (event.getClass() == UdpEvent.class) {
			UdpEvent udpEvent = (UdpEvent )event
			return processBootPMessage(udpEvent.udpMessage)
		}
	}
	
	static processBootPMessage(message) {
		BootpEvent bpe = new BootpEvent()
		bpe.opcode = message[0]
		bpe.hardwareAddressLength = message[2]
		bpe.clientIpAddress = PcapIOUtilities.byteArrayToIpString(message[12..15])
		bpe.yourIpAddress = PcapIOUtilities.byteArrayToIpString(message[16..19])
		bpe.serverIpAddress = PcapIOUtilities.byteArrayToIpString(message[20..23])
		bpe.gatewayIpAddress = PcapIOUtilities.byteArrayToIpString(message[24..27])
		bpe.clientHardwareAddress = PcapIOUtilities.bytesToHex(message[28..(28 + bpe.hardwareAddressLength - 1)])
		bpe.serverName = PcapIOUtilities.byteArrayToRaw(message[44..107])
		bpe.bootpFile = PcapIOUtilities.byteArrayToRaw(message[108..235])
		def vendorPayload = message[236..(message.size() - 1)]
		if(vendorPayload[0..3] == PcapConstants.bootpVendorMagicWord) {
			def vendorCursor = 4, code, chunkSize
			while(vendorCursor < vendorPayload.size()) {
				code = vendorPayload[vendorCursor]
				vendorCursor++
				if(code != 0 && vendorPayload[vendorCursor]) {
					chunkSize = (int )vendorPayload[vendorCursor]
					vendorCursor++
					if(code == 12) {
						bpe.bootpName = PcapIOUtilities.byteArrayToReadable(vendorPayload[vendorCursor..(vendorCursor + chunkSize - 1)]).toString()
					}
					vendorCursor += chunkSize
				}
			}
		}
		return bpe
	}
}