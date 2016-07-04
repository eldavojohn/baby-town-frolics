/**
 * 
 */
package org.eldavojohn.pcap

import static groovy.io.FileType.FILES
import static groovyx.gpars.actor.Actors.*
import groovy.util.logging.Log4j

import org.apache.log4j.Level
import org.apache.log4j.Logger
import org.eldavojohn.pcap.application.HttpRequestEvent
import org.eldavojohn.pcap.events.CommunicationEvent
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
class PcapParserTest {
	final static String PCAP_FOLDER = "../pcap-archive/"
	def accumulatorActor
	def ipAddressTotal
	def domainTotal
	def getTotal
	HashSet<String> ipAddressSet

	/**
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
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
		this.ipAddressSet = new HashSet<String>()
		this.ipAddressTotal = 0
		this.domainTotal = 0
		this.getTotal = 0
		this.accumulatorActor = actor {
			loop {
				react { CommunicationEvent pcapEvent ->
					if(pcapEvent.srcIpAddress) {
						this.ipAddressTotal++
						this.ipAddressSet.add(pcapEvent.srcIpAddress)
					}
					if(pcapEvent.dstIpAddress) {
						this.ipAddressSet.add(pcapEvent.dstIpAddress)
					}
					if(pcapEvent.subEvents) {
						pcapEvent.subEvents.each {
							if(it.subEvents) {
								it.subEvents.each { subEvent ->
									if(subEvent instanceof HttpRequestEvent) {
										if(subEvent.action == "GET") {
//											print subEvent.host
//											println subEvent.fullUri
											this.getTotal++
										}
										if(subEvent.host) {
											this.domainTotal++
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test() {
		new File(PCAP_FOLDER).eachFileRecurse(FILES) {
			if(it.name.endsWith('.pcap') || it.name.endsWith('.pcapng')) {
				log.info "Processing pcap file " + it.absolutePath
				new PcapBufferHandler(it.absolutePath)
			}
		}
	}
	
	@Test
	public void testAnitasHouse() {
		// Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/anitas-house.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		def tss = source.tcpSessionStore
		def ackNumbers = source.tcpSessionStore.ackNumbers.size()
		def ackRegistry = source.tcpSessionStore.ackRegistry.size()
		def sessionRegistry = source.tcpSessionStore.sessionRegistry.size()
		def sessionRegistryHandshakes = source.tcpSessionStore.sessionRegistryHandshakes.size()
		def synNumbersPlusOne = source.tcpSessionStore.synNumbersPlusOne.size()
		def synRegistry = source.tcpSessionStore.synRegistry.size()
		source.tcpSessionStore.sessionRegistry.each { key, value ->
			if(value && value != [0, 0] && value != [0, 0, 0, 0, 0, 0]) {
				println key + " -> " + value
			}
		}
		assert(this.ipAddressSet.size() == 246)
		assert(this.ipAddressTotal == 25609)
		assert(this.domainTotal == 832)
		assert(this.getTotal == 826)
		assert(source.packetCount == 27145)
	}
	
	@Test
	public void testPromiscuousAirport2() {
		Logger.getRootLogger().setLevel(Level.ERROR)
		def start = System.currentTimeMillis()
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/promiscuous-airport-2.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)  
		def now = System.currentTimeMillis()  
		println "Time to run: " + (now - start)/1000 + " seconds "  
		assert(this.ipAddressSet.size() == 1559)
		assert(this.ipAddressTotal == 115026)
		// assert(source.packetCount == 130421)
	}
	
	@Test
	public void testPromiscuousAnitasHouse() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/promiscuous-anita-house.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 145)
		assert(this.ipAddressTotal == 27223)
		assert(source.packetCount == 29169)
	}
	
	@Test
	public void testHttpChunkedGzip() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/http-chunked-gzip.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 1)
		assert(this.ipAddressTotal == 28)
		assert(source.packetCount == 28)
	}
	
	@Test
	public void testIperfMpTcp() { //TODO broke
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/iperf-mptcp-0-0.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		println this.ipAddressSet.size()
		println this.ipAddressTotal
		assert(source.packetCount == 6826)
	}
	
	@Test
	public void testNewAirport() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/newairport1.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 359)
		assert(this.ipAddressTotal == 5501)
		assert(source.packetCount == 6826)
	}
	
	@Test
	public void testPromiscuousAirport1() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/promiscuous-airport-1.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 359)
		assert(this.ipAddressTotal == 5501)
		assert(source.packetCount == 6826)
	}
	
	@Test
	public void testTcpEn() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/tcp-ecn-sample.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 2)
		assert(this.ipAddressTotal == 479)
		assert(source.packetCount == 479)
	}
	
	@Test
	public void testWlan() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/wlan.pcap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 39)
		assert(this.ipAddressTotal == 1520)
		assert(source.packetCount == 1895)
	}
	
	@Test
	public void testHttp() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/Http.cap")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 39)
		assert(this.ipAddressTotal == 1520)
		assert(source.packetCount == 1895)
	}
	
	@Test
	public void testDHCPBigEndian() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/dhcp_big_endian.pcapng")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 4)
		assert(this.ipAddressTotal == 4)
		assert(source.packetCount == 4)
	}
	
	@Test
	public void testDHCPLittleEndian() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/dhcp_little_endian.pcapng")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 4)
		assert(this.ipAddressTotal == 4)
		assert(source.packetCount == 4)
	}
	
	@Test
	public void testDHCP() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/dhcp.pcapng")
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 4)
		assert(this.ipAddressTotal == 4)
		assert(source.packetCount == 4)
	}
	
	@Test
	public void testManyInterfaces() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler pbh = new PcapBufferHandler("src/test/resources/many_interfaces.pcapng")
		pbh.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 8)
		assert(this.ipAddressTotal == 62)
		assert(pbh.packetCount == 64)
	}

}
