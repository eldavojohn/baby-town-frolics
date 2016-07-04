package org.eldavojohn.pcap

import static groovyx.gpars.actor.Actors.*
import groovy.util.logging.Log4j

import org.eldavojohn.pcap.configuration.PcapConfigurationAndRegistry
import org.eldavojohn.pcap.io.PcapBufferHandler

@Log4j
public class PcapParser {
	public static void main(String[] args) {
		PcapConfigurationAndRegistry pcapProperties = new PcapConfigurationAndRegistry(PcapConstants.PROPERTIES_LOCATION)
		def pcapFileName = "src/test/resources/anitas-house.pcap"
		log.info "Beginning processing of ${pcapFileName} at ${new Date()}"
		PcapBufferHandler source = new PcapBufferHandler(pcapFileName, pcapProperties.config)
		final def console = actor {
			loop {
				react { pcapEvent ->
					println 'Result: ' + pcapEvent
				}
			}
		}
		source.ingest()
		// source.ingestWithThreadHandler(console)
		if(!source.keepReading) {
			log.info "Completed processing of ${pcapFileName} at ${new Date()}"
		}
	}
}
