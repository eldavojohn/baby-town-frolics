package org.eldavojohn.pcap.configuration

import static org.junit.Assert.*

import org.junit.Before
import org.junit.Test

class ProtocolPortReferenceTest {
	ProtocolPortReference ppr

	@Before
	public void setUp() throws Exception {
		this.ppr = new ProtocolPortReference()
		this.ppr.loadPortMappingsFromFile()
	}

	@Test
	public void testPortProtocolLoading() {
		assert(this.ppr.portProtocols.size() == 6054)
		def sshPortProtocols = this.ppr.portProtocols.get(22)
		for(protocol in sshPortProtocols.values()) {
			assert(protocol.serviceName == "ssh")
		}
		def xnsTimePortProtocols = this.ppr.portProtocols.get(52)
		for(protocol in xnsTimePortProtocols.values()) {
			assert(protocol.serviceName == "xns-time")
		}
	}
}
