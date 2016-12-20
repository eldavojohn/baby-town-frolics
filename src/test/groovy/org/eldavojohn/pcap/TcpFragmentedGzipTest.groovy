/**
 * 
 */
package org.eldavojohn.pcap

import static org.junit.Assert.*

import org.apache.log4j.Level
import org.eldavojohn.pcap.configuration.PcapConfigurationAndRegistry
import org.eldavojohn.pcap.io.PcapBufferHandler
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test

import groovy.util.logging.Log4j

/**
 * @author eldavojohn
 *
 */

@Log4j
class TcpFragmentedGzipTest {
	
	static final String TEST_FILE = "src/test/resources/http-chunked-gzip.pcap"
	private PcapBufferHandler source
	
	/**
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		log.level = Level.ERROR
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		def pcapProperties = new PcapConfigurationAndRegistry(PcapConstants.PROPERTIES_LOCATION).config
		source = new PcapBufferHandler(TEST_FILE, pcapProperties)
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
		source = null
	}

	@Test
	public void test() {
		source.ingest()
		assert(true)
	}

}
