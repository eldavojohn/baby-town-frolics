package org.eldavojohn.pcap.transport

import org.eldavojohn.pcap.application.HttpProcessor
import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.io.PcapIOUtilities

class TcpHandler {
	static void processTcpMessage(byte[] payload, CommunicationEvent ce) {
		// extract header
		TcpEvent te = new TcpEvent()
		
		def sourcePort = Integer.parseInt(PcapIOUtilities.bytesToHex(payload[0..1]), 16)
		te.sourcePort = sourcePort
		def destinationPort = Integer.parseInt(PcapIOUtilities.bytesToHex(payload[2..3]), 16)
		te.destinationPort = destinationPort
		def sequence_number = Long.parseLong(PcapIOUtilities.bytesToHex(payload[4..7]), 16)
		te.sequenceNumber = sequence_number
		def ack_number = Long.parseLong(PcapIOUtilities.bytesToHex(payload[8..11]), 16)
		te.acknowledgementNumber = ack_number
		int data_offset = ((payload[12] >> 4) & 0xF)
		boolean ecn_nonce_concealment_protection = payload[12]  & 0b1
		te.ecn_nonce_concealment_protection = ecn_nonce_concealment_protection
		boolean finalized = payload[13]                         & 0b1
		te.finalized = finalized
		boolean synchronize_sequence_numbers = (payload[13] >>> 1)      & 0b1
		te.synchronize_sequence_numbers = synchronize_sequence_numbers
		boolean connection_reset = (payload[13] >>> 2)                  & 0b1
		te.connection_reset = connection_reset
		boolean push_buffered_data_to_application = (payload[13] >>> 3) & 0b1
		te.push_buffered_data_to_application = push_buffered_data_to_application
		boolean acknowledgment_number_important = (payload[13] >>> 4)   & 0b1
		te.acknowledgment_number_important = acknowledgment_number_important
		boolean urgent_pointer_field = (payload[13] >>> 5)              & 0b1
		te.urgent_pointer_field = urgent_pointer_field
		boolean ecn_echo = (payload[13] >>> 6)                          & 0b1
		te.ecn_echo = ecn_echo
		boolean congestion_window_reduced = (payload[13] >>> 7)         & 0b1
		te.congestion_window_reduced = congestion_window_reduced
		// log.info "flags " + payload[13]
		
		if((data_offset*4) <= (payload.size() - 1)) {
			payload = payload[(data_offset*4)..(payload.size() - 1)]
			te.tcpMessage = payload
		} else {
			te.tcpMessage = []
		}
		// def rawString = new String(PcapIOUtilities.byteArrayToRaw(payload))
		// log.info rawString.substring(0, 20) + "..."
		ce.subEvents.add(te)
	}

}
