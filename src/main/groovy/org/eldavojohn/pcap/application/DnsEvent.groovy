package org.eldavojohn.pcap.application

class DnsEvent {
	byte[] dnsId, flagsAndCodes
	boolean request
	int  questionCount, answerCount, nameServerCount, additionalCount
	ArrayList<String> queryDomains = new ArrayList<String>()
}
