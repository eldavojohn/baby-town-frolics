package org.eldavojohn.pcap.application

import groovy.util.logging.Log4j

import org.eldavojohn.pcap.actors.DefaultConsoleActor
import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.events.UdpEvent

@Log4j
class CommunicationEventProcessor {
	
	static processFinalEvent(CommunicationEvent finalStoreEvent, config, userActor) {
		finalStoreEvent.subEvents.each { subEvent ->
			 if(config.pcap.modules.tcp && subEvent.getClass() == TcpEvent.class) {
				TcpEvent tcpEvent = (TcpEvent )subEvent
				config.pcap.modules.tcp.each { name, value -> 
					def processorClass = value.processorClass
					def ports = value.ports
					
					if(ports == -1 || (ports.contains(tcpEvent.destinationPort) || ports.contains(tcpEvent.sourcePort))) {
						tcpEvent.subEvents.add(processorClass.processEvent(tcpEvent))
					}
				}
			} else if (config.pcap.modules.udp && subEvent.getClass() == UdpEvent.class) {
				UdpEvent udpEvent = (UdpEvent )subEvent
				config.pcap.modules.udp.each { name, value -> 
					def processorClass = value.processorClass
					def ports = value.ports
					
					if(ports == -1 || (ports.contains(udpEvent.destinationPort) || ports.contains(udpEvent.sourcePort))) {
						udpEvent.subEvents.add(processorClass.processEvent(udpEvent))
					}
				}
			}
		}
		if (userActor) {
			userActor << finalStoreEvent
		} else {
			DefaultConsoleActor.buildToConsole(finalStoreEvent)
		}
	}

}
