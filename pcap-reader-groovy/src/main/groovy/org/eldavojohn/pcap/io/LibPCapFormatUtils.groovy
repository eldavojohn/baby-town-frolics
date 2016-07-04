package org.eldavojohn.pcap.io

import groovy.util.logging.Log4j

import org.eldavojohn.pcap.physical.Spec8023Handler
import org.eldavojohn.pcap.physical.Spec80211Handler

@Log4j
class LibPCapFormatUtils {
	static processLibPcapPacketBlock(blockData, timeStampMilliSeconds, packetLength, totalBlockSize, tcpSessionStore, config, swap, linktype, keepReading) {
		if(linktype == 1) { // 802.3
			Spec8023Handler.processPacketBlock(packetLength, blockData, totalBlockSize, timeStampMilliSeconds, tcpSessionStore, config, swap)
		} else if(linktype == 105) { // 802.11
			Spec80211Handler.processPacketBlock(packetLength, blockData, totalBlockSize, timeStampMilliSeconds, tcpSessionStore, config, swap)
		} else {
			log.warn "Couldn't recognize linktype of " + linktype
		}
	}
}
