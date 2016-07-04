package org.eldavojohn.pcap.application

import java.util.HashMap;

class HttpRequestEvent {
	String action, host, fullUri, body, protocolVersion, acceptLanguage, acceptEncoding
	HashMap<String, String> headers
	
	def HttpRequestEvent(action) {
		this.action = action
	}
}
