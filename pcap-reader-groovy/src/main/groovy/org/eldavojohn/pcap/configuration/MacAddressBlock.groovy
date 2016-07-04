package org.eldavojohn.pcap.configuration

class MacAddressBlock {
	def beginningOctets
	HashSet<MacOwner> owners = new HashSet<MacOwner>()
	TreeMap<Long, MacIabOwner> iabOwners = new HashMap<Long, MacIabOwner>()
}
