package org.eldavojohn.pcap.configuration

import java.util.HashMap

import groovy.util.logging.Log4j

@Log4j
class ProtocolPortReference {
	private HashMap<Integer, HashMap<String, ProtocolPort>> portProtocols = new HashMap<Integer, HashMap<String, ProtocolPort>>()

	def loadPortMappingsFromFile() {
		def lineIndex = 0, currentLineCount = 0
		def currentMacPrefix = null, macOctet = "", currentAddress = new MacOwner()
		new File('src/main/resources/portProtocols.csv').eachLine { line ->
			if(lineIndex > 0) {
				line = line + ",placeholder" // split seems to trim trailing empties
				def c = line.trim().split(",").size()
				def chunks = line.trim().split(",")
				if(chunks.size() > 1) {
					try {
						def protocolList = new HashMap<String, ProtocolPort>()
						def port = Integer.parseInt(chunks[1])
						if(port == 52) {
							def protocolLista = portProtocols.get(port)
						}
						if(port && port > 0) {
							if(portProtocols.containsKey(port)) {
								protocolList = portProtocols.get(port)
							}
							if(chunks.size() > 12) {
								def protocol = new ProtocolPort(
										chunks[0],
										port,
										chunks[2],
										chunks[3],
										chunks[4],
										chunks[5],
										chunks[6],
										chunks[7],
										chunks[8],
										chunks[9],
										chunks[10],
										chunks[11])
								if(!chunks[2].trim()) {
									chunks[2] = "*"
								}
								protocolList.put(chunks[2], protocol)
								portProtocols.put(port, protocolList)
							}
						}
					} catch (Exception e) {
						log.debug("Couldn't parse the protocol integer from this line: " + line, e)
					}
				}
			}
			lineIndex++
		}
	}
}
