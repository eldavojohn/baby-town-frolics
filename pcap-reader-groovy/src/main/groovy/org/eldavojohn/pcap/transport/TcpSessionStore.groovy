package org.eldavojohn.pcap.transport

import groovy.util.logging.Log4j

import org.eldavojohn.pcap.PcapConstants
import org.eldavojohn.pcap.application.HttpProcessor
import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.io.PcapIOUtilities

@Log4j
class TcpSessionStore {

	private HashMap<String, Integer> ackRegistry = new HashMap<String, Integer>()
	private HashMap<String, Integer> synRegistry = new HashMap<String, Integer>()
	private HashMap<String, byte[]> sessionRegistry = new HashMap<String, byte[]>()
	private HashMap<String, Integer> sessionRegistryHandshakes = new HashMap<String, Integer>()
	private HashMap<String, Date> sessionTimestamp = new HashMap<String, Date>()
	private Set<Integer> synNumbersPlusOne = new HashSet<Integer>()
	private Set<Integer> ackNumbers = new HashSet<Integer>()
	
	def storeEvent(CommunicationEvent ce) {
		// behavior is not working for multi subevents -- have to return a collection?
		ce.subEvents.each { subEvent ->
			if(subEvent.class.equals(TcpEvent.class)) {
				subEvent.tcpMessage = storeTcpEvent(ce.srcMacAddress, ce.dstMacAddress, ce.srcIpAddress, ce.dstIpAddress, subEvent)
			}
		}
	}

	def storeTcpEvent(String srcMac, String dstMac, String srcIp, String dstIp, TcpEvent te) {
		
		def synHash = "$srcMac$srcIp${te.sourcePort}"
		def ackHash = "$dstMac$dstIp${te.destinationPort}"
		if(te.synchronize_sequence_numbers) {
			// syn is set so we must record this as the ISN
			if(ackNumbers.contains(te.sequenceNumber)) {
				log.info "syn matched to ack"
			}
			this.synRegistry.put(synHash, te.sequenceNumber + 1)
			this.synNumbersPlusOne.add(te.sequenceNumber + 1)
		}
		if(te.acknowledgment_number_important) {
			// syn is set so we must record this as the ISN
			if(synNumbersPlusOne.contains(te.acknowledgementNumber)) {
				log.info "ack matched to syn"
				if(!this.synRegistry.containsKey(ackHash)) {
					log.error "Acknowledgement number was not found in synchronized registry"
				}
			}
			this.ackRegistry.put(ackHash, te.acknowledgementNumber)
			this.ackNumbers.add(te.acknowledgementNumber)
			if(this.sessionRegistry.containsKey(ackHash)) {
				ArrayList<Byte> addition = this.sessionRegistry.get(ackHash)
				addition.addAll(te.tcpMessage)
				this.sessionRegistry.put(ackHash, addition as byte[])
			} else {
				this.sessionRegistry.put(ackHash, te.tcpMessage)
			}
		}

		if(te.synchronize_sequence_numbers && !te.acknowledgment_number_important) {
			// if it's only the syn flag that's set, we need to register the sequence number + 1 (ISN) and look for the IP address to return it as the ack number
			log.info "handshake 1: starting tcp session with sequence number " + te.sequenceNumber + " payload of " + te.tcpMessage.size() // 1337046631, 151609390, 685490547, 1287628360
			if(this.sessionRegistryHandshakes.containsKey(ackHash)) {
				// TODO need to figure out handshake actions if any
			}
			this.sessionRegistryHandshakes.put(ackHash, 1)
			// tcpSessionStore.stepOneHandShakeToIp(initial_sequence_number, "$sourceIpAddress$sourcePort")
		} else if(te.synchronize_sequence_numbers && te.acknowledgment_number_important) {
			log.info "handshake 2: response to starting tcp session with sequence number of " + te.sequenceNumber + " and ack_number of " + te.acknowledgementNumber + " payload of " + te.tcpMessage.size()
			if(this.sessionRegistryHandshakes.containsKey(ackHash) != 1) {
				// TODO need to figure out handshake actions if any
			}
			this.sessionRegistryHandshakes.put(ackHash, 2)
			// tcpSessionStore.stepTwoHandShakeFromIp(ack_number, "$destinationIpAddress$destinationPort")
		} else if(te.acknowledgment_number_important && !te.synchronize_sequence_numbers && te.tcpMessage.size() == 0) {
			log.info "handshake 3: starting tcp session with sequence number of " + te.sequenceNumber + " and ack_number of " + te.acknowledgementNumber
			if(this.sessionRegistryHandshakes.containsKey(ackHash) != 2) {
				// TODO need to figure out handshake actions if any
			}
			this.sessionRegistryHandshakes.put(ackHash, 3)
		} else if(te.acknowledgment_number_important && te.push_buffered_data_to_application) {
			log.info "transmitting data in this packet to the application of size " + te.tcpMessage.size()
		} else if(te.acknowledgment_number_important && !te.synchronize_sequence_numbers) {
			log.info "normal data transmission from one endpoint to the other of size " + te.tcpMessage.size()
		}
		
		if(te.finalized || te.push_buffered_data_to_application) {
			log.info "FINALIZED or push!"
			// return a session object
			this.sessionRegistryHandshakes.remove(ackHash)
			byte[] totalMessage = Arrays.copyOf(this.sessionRegistry.get(ackHash), this.sessionRegistry.get(ackHash).size())
			this.sessionRegistry.remove(ackHash)
			return totalMessage
		} else {
			return null
		}
	}

	def stepOneHandShakeToIp(int ackNumber, String ip) {
		ackNumber++
		def hash = "$ip$ackNumber"
		ackRegistry.put(ip, ackNumber)
		sessionRegistry.put(hash, new byte[0])
		sessionTimestamp.put(hash, new Date())
	}

	def stepTwoHandShakeFromIp(int synNumber, String ip) {
		if(!ackRegistry.get(ip)) {
			log.info "We missed step one!"
		}
		def hash = "$ip$synNumber"
		synRegistry.put(ip, synNumber)
		sessionRegistry.put(hash, new byte[0])
		sessionTimestamp.put(hash, new Date())
	}

	def stepThreeHandShakeToIp(int ackNumber, String ip) {
	}
}
