package org.eldavojohn.pcap.application

import groovy.util.logging.Log4j

import org.eldavojohn.pcap.PcapConstants
import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.io.PcapIOUtilities


@Log4j
class HttpProcessor {

	static processEvent(TcpEvent te) {
		if(te.tcpMessage) {
			if(te.tcpMessage.size() > 3 && te.tcpMessage[0..3] == PcapConstants.CH_HTTP) {
				return HttpProcessor.processResponse(te.tcpMessage)
			} else if(te.tcpMessage.size() > 2 && te.tcpMessage[0..2] == PcapConstants.CH_GET) {
				return HttpProcessor.processAction(te.tcpMessage, "GET")
			} else if(te.tcpMessage.size() > 3 && te.tcpMessage[0..3] == PcapConstants.CH_HEAD) {
				return HttpProcessor.processAction(te.tcpMessage, "HEAD")
			} else if(te.tcpMessage.size() > 3 && te.tcpMessage[0..3] == PcapConstants.CH_POST) {
				return HttpProcessor.processAction(te.tcpMessage, "POST")
			} else if(te.tcpMessage.size() > 2 && te.tcpMessage[0..2] == PcapConstants.CH_PUT) {
				return HttpProcessor.processAction(te.tcpMessage, "PUT")
			} else if(te.tcpMessage.size() > 5 && te.tcpMessage[0..5] == PcapConstants.CH_DELETE) {
				return HttpProcessor.processAction(te.tcpMessage, "DELETE")
			} else if(te.tcpMessage.size() > 4 && te.tcpMessage[0..4] == PcapConstants.CH_TRACE) {
				return HttpProcessor.processAction(te.tcpMessage, "TRACE")
			} else if(te.tcpMessage.size() > 6 && te.tcpMessage[0..6] == PcapConstants.CH_OPTIONS) {
				return HttpProcessor.processAction(te.tcpMessage, "OPTIONS")
			} else if(te.tcpMessage.size() > 6 && te.tcpMessage[0..6] == PcapConstants.CH_CONNECT) {
				return HttpProcessor.processAction(te.tcpMessage, "CONNECT")
			} else if(te.tcpMessage.size() > 4 && te.tcpMessage[0..4] == PcapConstants.CH_PATCH) {
				return HttpProcessor.processAction(te.tcpMessage, "PATCH")
			}
		}
	}

	static processAction(payload, action) {
		def rawString = new String(PcapIOUtilities.byteArrayToRaw(payload))
		HttpRequestEvent hre = new HttpRequestEvent(action)
		def stringSet = rawString.split("\n")
		def lineCounter = 1
		HashMap<String, String> headers = null
		(headers, lineCounter) = getHeadersFromLineIndex(stringSet, lineCounter)
		// Host=sales.liveperson.net, Accept-Encoding=gzip, deflate, sdch, Accept-Language=en-US,en;q=0.8
		if(headers.get("Host")) {
			hre.host = headers.get("Host")
		}
		if(headers.get("Accept-Encoding")) {
			hre.acceptEncoding = headers.get("Accept-Encoding")
		}
		if(headers.get("Accept-Language")) {
			hre.acceptLanguage = headers.get("Accept-Language")
		}
		hre.headers = headers
		if(action == "GET") {
			log.info "GET request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "HEAD") {
			log.info "HEAD request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "POST") {
			log.info "POST request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "PUT") {
			log.info "PUT request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "OPTIONS") {
			log.info "OPTIONS request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "DELETE") {
			log.info "DELETE request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "TRACE") {
			log.info "TRACE request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "CONNECT") {
			log.info "CONNECT request process starting ... "
			processActionLine(stringSet[0], hre)
		} else if (action == "PATCH") {
			log.info "PATCH request process starting ... "
			processActionLine(stringSet[0], hre)
		} else {
			log.warn "Unrecognized request type of ${action}"
			processActionLine(stringSet[0], hre)
		}
		if(lineCounter < stringSet.size()) {
			hre.body = stringSet[lineCounter..(stringSet.size() - 1)].join("\n").trim()
		}
		return hre
	}
	
	static processActionLine(line, HttpRequestEvent hre) {
		def lineSet = line.split(" ")
		if(lineSet.size() > 1) {
			hre.fullUri = lineSet[1]
		}
		if(lineSet.size() > 2) {
			hre.protocolVersion = lineSet[2]
		}
	}

	static processResponse(payload) {
		HttpResponseEvent hre = new HttpResponseEvent()
		def stringSet = new String(PcapIOUtilities.byteArrayToRaw(payload)).split("\n")
		def line = stringSet[0]

		def statusSet = line.split(' ')
		def statusSize = statusSet.size()
		if(statusSize > 0) {
			hre.protocol = statusSet[0]
			if(statusSize > 1) {
				try {
					hre.code = Integer.parseInt(statusSet[1])
				} catch (e) {
					log.warn "Couldn't parse an HTTP status code to an integer.", e
				}
				if(statusSize > 2) {
					hre.msg = statusSet[2]
				}
			}
		}
		def lineCounter = 1
		HashMap<String, String> headers = null
		(headers, lineCounter) = getHeadersFromLineIndex(stringSet, lineCounter)
		hre.headers = headers
		if(lineCounter < stringSet.size()) {
			hre.body = stringSet[lineCounter..(stringSet.size() - 1)].join("\n").trim()
		}
		return hre
	}

	static getHeadersFromLineIndex(stringSet, lineCounter) {
		def headers = new HashMap<String, String>()
		headers.put("keyless", [])
		if(stringSet.size() > lineCounter) {
			def line = stringSet[lineCounter]
			while(line.trim() && lineCounter < stringSet.size()) {
				def headerObj = processHeaderLine(line)
				if(!headerObj["name"]) {
					headers.get("keyless").add(headerObj["value"])
				} else {
					headers.put(headerObj["name"], headerObj["value"])
				}
				lineCounter++
				if(lineCounter < stringSet.size()) {
					line = stringSet[lineCounter]
				}
			}
		}
		return [ headers, lineCounter ]
	}

	static processHeaderLine(headerLine) {
		def result = [ name: "", value: ""]
		def pair = headerLine.split(':')
		if(pair.size() >= 2) {
			result["name"] = pair[0].trim()
			result["value"] = pair[1..(pair.size() - 1)].join(":").trim()
		} else {
			result["name"] = ""
			result["value"] = headerLine.trim()
		}
		return result
	}
}
