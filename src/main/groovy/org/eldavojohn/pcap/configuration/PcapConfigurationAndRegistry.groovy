package org.eldavojohn.pcap.configuration

import groovy.util.logging.Log4j

@Log4j
class PcapConfigurationAndRegistry {
	ConfigObject config
	
	def PcapConfigurationAndRegistry(String location="src/main/resources/pcap.properties") {
		this.config = new ConfigSlurper().parse(new File(location).toURI().toURL())
	}
	
	def downloadIdentificationFiles() {
		def url, file
		url = this.config.pcap.identification.ieeeOuiFile
		file = new File('src/main/resources/ieeOui.txt').newOutputStream()
		log.info "Downloading oui file ..."
		file << new URL(url).openStream()
		file.close()
		url = this.config.pcap.identification.ieeeIabFile
		file = new File('src/main/resources/ieeIab.txt').newOutputStream()
		log.info "Downloading iee iab file ..."
		file << new URL(url).openStream()
		file.close()
		url = this.config.pcap.identification.ieeeOui36File
		file = new File('src/main/resources/ieeOui36.txt').newOutputStream()
		log.info "Downloading oui 36 file ..."
		file << new URL(url).openStream()
		file.close()
		url = this.config.pcap.identification.portProtocolFile
		file = new File('src/main/resources/portProtocols.csv').newOutputStream()
		log.info "Downloading port protocols file ..."
		file << new URL(url).openStream()
		file.close()
	}
	
	def getPcapModules() {
		return this.config.pcap.modules.flatten()
	}
}
