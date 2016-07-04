package org.eldavojohn.pcap

import org.eldavojohn.pcap.configuration.PcapConfigurationAndRegistry

class IdentificaionFileDownloader {
	static main(args) {
		PcapConfigurationAndRegistry pcapProperties = new PcapConfigurationAndRegistry(PcapConstants.PROPERTIES_LOCATION)
		pcapProperties.downloadIdentificationFiles()
	}
}
