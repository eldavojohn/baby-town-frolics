package org.eldavojohn.pcap.configuration

import java.util.HashSet

class MacIabOwner {
	Long rangeStart, rangeEnd
	HashSet<MacOwner> owners = new HashSet<MacOwner>()
}
