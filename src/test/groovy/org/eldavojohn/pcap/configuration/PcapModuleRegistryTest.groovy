package org.eldavojohn.pcap.configuration

import static org.junit.Assert.*

import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test

class PcapModuleRegistryTest {
	
	private pcapProperties
	static final String location = "src/test/resources/pcap.properties"

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
		pcapProperties = new PcapConfigurationAndRegistry(location)
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test() {
		println "start"
		def moduleMap = pcapProperties.config.pcap.modules.tcp.flatten()
		moduleMap.each { prop, val ->
			println prop + " " + val
		}
		assert(pcapProperties.config.pcap.modules.tcp.http.ports == "-1")
	}

}
