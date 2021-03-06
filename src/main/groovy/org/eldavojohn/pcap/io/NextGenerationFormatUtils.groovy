package org.eldavojohn.pcap.io

import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.link.Ethernet2Handler
import org.eldavojohn.pcap.physical.Spec80211Handler
import org.eldavojohn.pcap.physical.Spec8023Handler

import groovy.util.logging.Log4j

@Log4j
class NextGenerationFormatUtils {
	static processPacketBlock(blockData, totalBlockSize, swap, config, tcpSessionStore, linktype) {
		if(linktype == 1) { // 802.3
			// Spec8023Handler.processPacketBlock(packetLength, blockData, totalBlockSize, timeStampMilliSeconds, tcpSessionStore, config, swap)
			log.info "Interface ID " + Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[0..3], swap)), 16)
			long timeStampHigh = (long )PcapIOUtilities.bytesToInt(PcapIOUtilities.orderBytes(blockData[4..7], swap))
			long timeStampLow = (long )PcapIOUtilities.bytesToInt(PcapIOUtilities.orderBytes(blockData[8..11], swap))
			long composedDateMs = (long )((((timeStampHigh) << 32) | (timeStampLow & 0x00000000FFFFFFFFL))/1000L)
			def timestamp = new Date(composedDateMs)
			log.info "Timestamp " + timestamp
			def capturedPacketLength = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[12..15], swap)), 16)
			def packetLength = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[16..19], swap)), 16)
			log.info "Captured Packet Length " + capturedPacketLength
			log.info "Original Packet Length " + packetLength
			def payload = blockData[20..(20 + packetLength - 1)] // PcapIOUtilities.byteArrayToReadable(blockData[28..(28 + packetLength)])
			// log.info "Packet payload: " + payload
			CommunicationEvent ce = new CommunicationEvent()
			ce.packetBlockTimestamp = timestamp
			Ethernet2Handler.processLayer2(payload, config, ce)
	
			// deal with communication events in variable ce
			tcpSessionStore.storeEvent(ce)
	
			packetLength += PcapIOUtilities.padTo32(packetLength)
			if(blockData.size() > 2 + 20 + packetLength) {
				println "Section Options " + processBlockOptions(blockData, 20 + packetLength, swap)
			}
			return ce
		} else if(linktype == 105) { // 802.11
			// Spec80211Handler.processPacketBlock(packetLength, blockData, totalBlockSize, timeStampMilliSeconds, tcpSessionStore, config, swap)
		} else if(linktype == 127) { // 802.11 + Radio tap
			// TODO what are these 20 bytes that precede the radiotap header?!
			blockData = blockData[20..(blockData.size() - 1)]
			def interfaceId = blockData[0]
			def uselessPadding = blockData[1]
			def wiretapHeaderLength = PcapIOUtilities.bytesToInt(PcapIOUtilities.orderBytes(blockData[2..3], swap))
			def fieldsPresent = PcapIOUtilities.bytesToInt(PcapIOUtilities.orderBytes(blockData[4..7], swap))
			blockData = blockData[wiretapHeaderLength..(blockData.size() - 1)]
			Spec80211Handler.processPacketBlock(blockData.size() - 1, blockData, blockData.size() - 1, 5754754, tcpSessionStore, config, swap)
//			println blockData
//			println PcapIOUtilities.byteArrayToReadable(blockData)
		} else {
			log.warn "Couldn't recognize linktype of " + linktype
		}
	}

	static processBlockOptions(byte[] blockData, optionPosition, swap) {
		def optionEnd = false
		def optionLength = 0
		def opts = [:]
		while (!optionEnd) {
			def otype = PcapIOUtilities.orderBytes(blockData[optionPosition..(optionPosition+1)], swap)
			optionLength = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[(optionPosition + 2)..(optionPosition + 3)], swap)), 16)
			optionPosition += 4
			if(otype == [0, 0] && optionLength == 0) {
				optionEnd = true
			} else {
				opts.put(PcapIOUtilities.bytesToHex(otype), PcapIOUtilities.byteArrayToReadable(blockData[optionPosition..(optionPosition+optionLength)]))
				optionLength += PcapIOUtilities.padTo32(optionLength)
				optionPosition += optionLength
			}
		}
		return opts
	}

	static processSectionBlock(blockData, swap) {
		log.info "Major Version " + Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[4..5], swap)), 16)
		log.info "Minor Version " + Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[6..7], swap)), 16)
		// TODO why does this error? log.info "Section Options " + processBlockOptions(blockData, 16)
	}

	static processInterfaceStatsBlock(blockData, swap) {

	}
	
	static processNameResolutionBlock(blockData, swap) {

	}

	static processInterfaceBlock(blockData, totalBlockSize, swap) {
		def link_type = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[0..1], swap)), 16)
		log.info "Link Type " + link_type
		log.info "Reserved Type " + Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[2..3], swap)), 16)
		log.info "Snap Length " + Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[4..7], swap)), 16)
		return link_type
		// TODO why does this error? log.info "Section Options " + processBlockOptions(blockData, 16)
	}
}
