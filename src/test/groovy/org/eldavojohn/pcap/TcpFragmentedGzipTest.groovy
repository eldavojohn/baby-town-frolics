/**
 * 
 */
package org.eldavojohn.pcap

import static org.junit.Assert.*

import org.apache.log4j.Level

import groovy.util.logging.Log4j
import org.eldavojohn.pcap.io.PcapBufferHandler
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test

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
		source = new PcapBufferHandler(TEST_FILE)
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
		println source
		assert(true)
	}

}
