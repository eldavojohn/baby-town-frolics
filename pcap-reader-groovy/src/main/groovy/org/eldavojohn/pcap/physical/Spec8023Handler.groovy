package org.eldavojohn.pcap.physical

import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.io.NextGenerationFormatUtils
import org.eldavojohn.pcap.io.PcapIOUtilities
import org.eldavojohn.pcap.link.Ethernet2Handler

import groovy.util.logging.Log4j

@Log4j
class Spec8023Handler {
	static processPacketBlock(packetLength, blockData, totalBlockSize, timeStampMilliSeconds, tcpSessionStore, config, swap) {
		if(blockData.size() < totalBlockSize || blockData.size() < 16) {
			log.error "Failed to process LibPCap packet block as defined due to lack of block data for total block size."
			return null
		}
		try {
			CommunicationEvent ce = new CommunicationEvent()
			ce.packetBlockTimestamp = new Date(timeStampMilliSeconds)
			Ethernet2Handler.processLayer2(blockData, config, ce)

			// deal with communication events in variable ce
			tcpSessionStore.storeEvent(ce)

			packetLength += PcapIOUtilities.padTo32(packetLength)
			if(blockData.size() > 2 + 20 + packetLength) {
				// TODO is it worth our time to parse these block options?
				NextGenerationFormatUtils.processBlockOptions(blockData, 20 + packetLength, swap)
			}
			return ce
		} catch (Exception e) {
			log.error "Failed to process LibPCap packet block as defined", e
			return null
		}
	}
}
