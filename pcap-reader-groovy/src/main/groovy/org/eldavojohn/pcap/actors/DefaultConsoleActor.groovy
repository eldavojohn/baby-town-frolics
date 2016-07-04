package org.eldavojohn.pcap.actors

import org.eldavojohn.pcap.events.CommunicationEvent

class DefaultConsoleActor {
	static buildToConsole(CommunicationEvent ce) {
		String output = "$ce.packetBlockTimestamp : "
		output += "$ce.srcMacAddress -> $ce.dstMacAddress : "
		output += "$ce.srcIpAddress -> $ce.dstIpAddress "
		println output
		ce.subEvents.each {
			println it.inspect()
		}
	}
}
