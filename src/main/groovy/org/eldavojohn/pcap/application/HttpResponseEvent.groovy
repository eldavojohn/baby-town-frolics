package org.eldavojohn.pcap.application

class HttpResponseEvent {
	String body, protocol, msg
	int code
	HashMap<String, String> headers
}
