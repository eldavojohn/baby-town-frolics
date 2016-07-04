package org.eldavojohn.pcap.events

class TcpEvent {

	int sourcePort, destinationPort
	long sequenceNumber, acknowledgementNumber
	boolean ecn_nonce_concealment_protection, finalized, synchronize_sequence_numbers,
		connection_reset, push_buffered_data_to_application, acknowledgment_number_important,
		urgent_pointer_field, ecn_echo, congestion_window_reduced, session_fragment
		
	byte[] tcpMessage
	def subEvents = new ArrayList<Object>()
}
