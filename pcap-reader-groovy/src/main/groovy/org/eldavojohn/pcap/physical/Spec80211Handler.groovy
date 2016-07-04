package org.eldavojohn.pcap.physical

import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.io.NextGenerationFormatUtils
import org.eldavojohn.pcap.io.PcapIOUtilities
import org.eldavojohn.pcap.link.Ethernet2Handler

import groovy.util.logging.Log4j

@Log4j
class Spec80211Handler {
	static processPacketBlock(packetLength, blockData, totalBlockSize, timeStampMilliSeconds, tcpSessionStore, config, swap) {
		println PcapIOUtilities.bytesToHex(blockData)
		def version = blockData[0] & 0b11
		def type = blockData[0] >>> 2 & 0b11
		def subtype = blockData[0] >>> 4 & 0b1111
		def flags = PcapIOUtilities.bytesToHex([blockData[1]])
		def duration = PcapIOUtilities.bytesToHex(blockData[2..3])
		def receiverAddress = PcapIOUtilities.bytesToHex(blockData[4..9])
		if(type == 0) { // management frames
			if(subtype == 0 || subtype == 1 || subtype == 4 || subtype == 5 || subtype == 8 || subtype == 11 || subtype == 12) { 
				// 0: association request, 1: association response, 4: probe request, 5: probe response, 8: beacon, 11: authentication, 12: PS Poll
				def transmitterAddress = PcapIOUtilities.bytesToHex(blockData[10..15])
				def bssidAddress = PcapIOUtilities.bytesToHex(blockData[16..21])
				def fragmentNumberAndSequenceNumber = PcapIOUtilities.bytesToHex(blockData[22..23])
				if(subtype != 11 && subtype != 12) {
					def timestamp = PcapIOUtilities.bytesToHex(blockData[24..31])
					def beaconInterval = PcapIOUtilities.bytesToHex(blockData[32..33])
					def capabilities = PcapIOUtilities.bytesToHex(blockData[34..35])
					int parameterMarker = 35
					HashMap<String, String> params = new HashMap<String, String>()
					while(parameterMarker < blockData.size() - 1) {
						def tagNumber = blockData[++parameterMarker]
						def taglength = Integer.parseInt(PcapIOUtilities.bytesToHex([blockData[++parameterMarker]]), 16)
						if(parameterMarker + taglength < blockData.size() - 1) {
							def tagValue = PcapIOUtilities.byteArrayToReadable(blockData[parameterMarker..(parameterMarker + taglength)])
							params.put(tagNumber, tagValue)
						}
						parameterMarker = parameterMarker + taglength
					}
				}
			} else {
				print type
				println subtype
			}
		} else if(type == 1) { // control frames
			if (subtype == 13) { // ack
			} else {
				print type
				println subtype
			}
		} else if(type == 2) { // data
			def transmitterAddress = PcapIOUtilities.bytesToHex(blockData[10..15])
			def sourceAddress = PcapIOUtilities.bytesToHex(blockData[16..21])
			def sequenceAndfragmentNumber = PcapIOUtilities.bytesToHex(blockData[22..23])
			if(subtype != 4) {
				def tkipParameters = PcapIOUtilities.bytesToHex(blockData[24..31])
				def data = blockData[32..(blockData.size() - 1)]
			}
		} else {
			print type
			println subtype
		}
		if(blockData.size() < totalBlockSize || blockData.size() < 16) {
			log.error "Failed to process LibPCap packet block as defined due to lack of block data for total block size."
			return null
		}
		try {
			CommunicationEvent ce = new CommunicationEvent()
			ce.packetBlockTimestamp = new Date(timeStampMilliSeconds)
			Ethernet2Handler.processLayer2(blockData, config, ce)

			// deal with communication events in variable ce
			def finalTcpSession = tcpSessionStore.storeEvent(ce)

			packetLength += PcapIOUtilities.padTo32(packetLength)
			if(blockData.size() > 2 + 20 + packetLength) {
				log.info "Section Options " + NextGenerationFormatUtils.processBlockOptions(blockData, 20 + packetLength, swap)
			}
			return ce
		} catch (Exception e) {
			log.error "Failed to process LibPCap packet block as defined", e
			return null
		}
	}
}
