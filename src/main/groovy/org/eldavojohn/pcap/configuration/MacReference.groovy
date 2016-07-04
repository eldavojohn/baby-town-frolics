package org.eldavojohn.pcap.configuration

import groovy.util.logging.Log4j

@Log4j
class MacReference {
	private HashMap<String, MacAddressBlock> ouis = new HashMap<String, MacAddressBlock>()

	def loadOuisFromFile(ouiFile='src/main/resources/ieeOui.txt') {
		def lineIndex = 0, currentLineCount = 0
		def currentMacPrefix = null, macOctet = "", currentAddress = new MacOwner()
		new File(ouiFile).eachLine { line ->
			if(lineIndex > 3) {
				if (line.contains("(hex)")) {
					if(macOctet && ouis.containsKey(macOctet)) {
						// add to the existing MacAddressBlock
						currentMacPrefix = ouis.get(macOctet)
					} else if(macOctet) {
						currentMacPrefix = new MacAddressBlock()
					}
					if(currentMacPrefix) {
						currentMacPrefix.beginningOctets = macOctet
						currentMacPrefix.owners.add(currentAddress)
						ouis.put(macOctet, currentMacPrefix)
					}
					def pair = line.split("\\(hex\\)")
					if(pair.size() < 2) {
						log.warn "Unabe to parse line in OUI file: " + pair
					} else {
						currentAddress = new MacOwner()
						currentAddress.name = pair[1].trim()
						macOctet = pair[0].trim().replace("-", "")
						currentLineCount = 0
						currentMacPrefix = ""
					}
				} else if(line.contains("(base 16)")) {
					// example line FC-F1-52   (hex)		Sony Corporation
					def pair = line.split("\\(base 16\\)")
					if(pair.size() < 2) {
						log.warn "Unabe to parse line in OUI file: " + pair
					} else {
						currentAddress.mailingName = pair[1].trim()
					}
				} else if (currentAddress) {
					def cleanLine = line.trim()
					if(currentLineCount == 0) {
						currentAddress.addressLineOne = cleanLine
					} else if(currentLineCount == 1) {
						def addressSplit = cleanLine.split("  ")
						currentAddress.city = addressSplit[0]
						if(addressSplit.size() > 1) {
							currentAddress.state = addressSplit[1]
						}
						if(addressSplit.size() > 2) {
							currentAddress.zipCode = addressSplit[2]
						}
					} else if(currentLineCount == 2) {
						currentAddress.countryCode = cleanLine
					}
					currentLineCount++
				} else {
					log.warn "Confusing ordering of ingested OUI file's lines."
				}
			}
			lineIndex++
		}
		if(macOctet && ouis.containsKey(macOctet)) {
			// add to the existing MacAddressBlock
			currentMacPrefix = ouis.get(macOctet)
		} else if(macOctet) {
			currentMacPrefix = new MacAddressBlock()
		}
		if(currentMacPrefix) {
			currentMacPrefix.beginningOctets = macOctet
			currentMacPrefix.owners.add(currentAddress)
			ouis.put(macOctet, currentMacPrefix)
		}
	}

	def loadIabOuisFromFile(fileName) {
		def lineIndex = 0, currentLineCount = 0
		def currentMacPrefix = null, currentIab = null, macOctet = "", currentAddress = new MacOwner(), range
		new File(fileName).eachLine { line ->
			if(lineIndex > 3) {
				if (line.contains("(hex)")) {
					if(currentMacPrefix && currentIab) {
						currentIab.owners.add(currentAddress)
						currentMacPrefix.beginningOctets = macOctet
						currentMacPrefix.iabOwners.put(currentIab.rangeStart, currentIab)
						ouis.put(macOctet, currentMacPrefix)
						currentLineCount = 0
						currentMacPrefix = ""
					}
					def pair = line.split("\\(hex\\)")
					if(pair.size() < 2) {
						log.warn "Unabe to parse line in OUI file: " + pair
					} else {
						currentAddress = new MacOwner()
						currentAddress.name = pair[1].trim()
						macOctet = pair[0].trim().replace("-", "")
						currentIab = new MacIabOwner()
					}
					if(macOctet && ouis.containsKey(macOctet)) {
						// add to the existing MacAddressBlock
						currentMacPrefix = ouis.get(macOctet)
					} else {
						currentMacPrefix = new MacAddressBlock()
					}
				} else if(line.contains("(base 16)")) {
					// example line FC-F1-52   (hex)		Sony Corporation
					def pair = line.split("\\(base 16\\)")
					if(pair.size() < 2) {
						log.warn "Unabe to parse line in OUI file: " + pair
					} else {
						range = pair[0].trim().split("-")
						currentIab.rangeStart = Long.parseLong(range[0], 16)
						currentIab.rangeEnd = Long.parseLong(range[1], 16)
						currentAddress.mailingName = pair[1].trim()
					}
				} else if (currentAddress) {
					def cleanLine = line.trim()
					if(currentLineCount == 0) {
						currentAddress.addressLineOne = cleanLine
					} else if(currentLineCount == 1) {
						def addressSplit = cleanLine.split("  ")
						currentAddress.city = addressSplit[0]
						if(addressSplit.size() > 1) {
							currentAddress.state = addressSplit[1]
						}
						if(addressSplit.size() > 2) {
							currentAddress.zipCode = addressSplit[2]
						}
					} else if(currentLineCount == 2) {
						currentAddress.countryCode = cleanLine
					}
					currentLineCount++
				} else {
					log.warn "Confusing ordering of ingested OUI file's lines."
				}
			}
			lineIndex++
		}
		if(currentMacPrefix && currentIab) {
			currentIab.owners.add(currentAddress)
			currentMacPrefix.beginningOctets = macOctet
			currentMacPrefix.iabOwners.put(currentIab.rangeStart, currentIab)
			ouis.put(macOctet, currentMacPrefix)
			currentLineCount = 0
			currentMacPrefix = ""
		}
	}

	def retrieveMacData(String mac) {
		def cleanedMac = mac.split(":").join("").split("-").join("")
		if(cleanedMac.size() < 6) {
			return null
		} else if(cleanedMac.size() < 12) {
			def a = ouis.get(cleanedMac[0..5])
			return ouis.get(cleanedMac[0..5])
		} else {
			def oui = ouis.get(cleanedMac[0..5])
			if(oui.iabOwners.size() > 0 && cleanedMac.size() >= 12) {
				try {
					def macIndex = Long.parseLong(cleanedMac[6..11].toString(), 16)
					def iabList = oui.iabOwners
					def iab = iabList.get(macIndex)
					def potentialKey = 0L
					for (key in iabList.keySet()) {
						if(key <= macIndex) {
							potentialKey = key
						} else if(key > macIndex) {
							continue
						}
					}
					def potentialBlock = oui.iabOwners.get(potentialKey)
					if(macIndex >= potentialBlock.rangeStart && macIndex <= potentialBlock.rangeEnd) {
						return potentialBlock
					}
				} catch (Exception e) {
					log.warn("Unable to parse mac string to integer.", e)
				}
			}
			return ouis.get(cleanedMac[0..5])
		}
	}
}
