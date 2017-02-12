/**
 * 
 */
package org.eldavojohn.pcap

import static groovy.io.FileType.FILES
import static groovyx.gpars.actor.Actors.*

import org.apache.log4j.Level
import org.apache.log4j.Logger
import org.eldavojohn.pcap.application.HttpRequestEvent
import org.eldavojohn.pcap.configuration.PcapConfigurationAndRegistry
import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.io.PcapBufferHandler
import org.eldavojohn.pcap.validate.TsharkDriverAndReporter
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
class PcapParserTest {
	final static String PCAP_FOLDER = "../pcap-archive/"
	def accumulatorActor
	def ipAddressTotal
	def domainTotal
	def getTotal
	def tsharkloc
	def pcapProperties
	HashSet<String> ipAddressSet
	HashMap<String, Integer> ssidHashMap

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
		this.ssidHashMap = new HashMap<String, Integer>()
		this.ipAddressTotal = 0
		this.domainTotal = 0
		this.getTotal = 0
		this.pcapProperties = new PcapConfigurationAndRegistry(PcapConstants.PROPERTIES_LOCATION).config
		if(this.pcapProperties.pcap.testutilities && this.pcapProperties.pcap.testutilities.tsharkloc) {
			this.tsharkloc = this.pcapProperties.pcap.testutilities.tsharkloc
		}
		this.accumulatorActor = actor {
			loop {
				react { CommunicationEvent pcapEvent ->
					if(pcapEvent.ssidName) {
						if(this.ssidHashMap.get(pcapEvent.ssidName)) {
							this.ssidHashMap.put(pcapEvent.ssidName, this.ssidHashMap.get(pcapEvent.ssidName) + 1)
						} else {
							this.ssidHashMap.put(pcapEvent.ssidName, 1)
						}
					} 
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
				new PcapBufferHandler(it.absolutePath, this.pcapProperties)
			}
		}
	}
	
	@Test
	public void testAnitasHouse8023Wifi() {
		// Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/anitas-house.pcap", this.pcapProperties)
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
		// assert(source.packetCount == 27145)
	}
	
	@Test
	public void testAnitasHouseTrueWifi() {
		// Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/anitas-house-4.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		def resultSSIDHashMap = TsharkDriverAndReporter.runForField(this.tsharkloc, "src/test/resources/anitas-house-4.pcap", "wlan_mgt.ssid")
		println this.ssidHashMap.inspect()  // ['TP-LINK_5E1C':7, 'HOME-37AD-2.4':18, 'xfinitywifi':9, 'HOME-37AD-5':5]
		println resultSSIDHashMap.inspect() // ['TP-LINK_5E1C':7, 'HOME-37AD-2.4':19, 'xfinitywifi':9, 'HOME-37AD-5':5]
		
		// needless assert
		assert(resultSSIDHashMap == ['TP-LINK_5E1C':7, 'HOME-37AD-2.4':19, 'xfinitywifi':9, 'HOME-37AD-5':5])
		// TODO compare their ssid count to our ssid count
		// assert(source.packetCount == 27145)
	}
	
	@Test
	public void testPromiscuousAirport2() {
		Logger.getRootLogger().setLevel(Level.ERROR)
		def start = System.currentTimeMillis()
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/promiscuous-airport-2.pcap", this.pcapProperties)
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
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/promiscuous-anita-house.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 145)
		assert(this.ipAddressTotal == 27223)
		assert(source.packetCount == 29169)
	}
	
	@Test
	public void testHttpChunkedGzip() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/http-chunked-gzip.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 1)
		assert(this.ipAddressTotal == 28)
		assert(source.packetCount == 28)
	}
	
	@Test
	public void testIperfMpTcp() { //TODO broke
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/iperf-mptcp-0-0.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		println this.ipAddressSet.size()
		println this.ipAddressTotal
		assert(source.packetCount == 2561)
	}
	
	@Test
	public void testNewAirport() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/newairport1.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 359)
		assert(this.ipAddressTotal == 5501)
		assert(source.packetCount == 6826)
	}
	
	@Test
	public void testPromiscuousAirport1() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/promiscuous-airport-1.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 359)
		assert(this.ipAddressTotal == 5501)
		assert(source.packetCount == 6826)
	}
	
	@Test
	public void testTcpEn() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/tcp-ecn-sample.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 2)
		assert(this.ipAddressTotal == 479)
		assert(source.packetCount == 479)
	}
	
	@Test
	public void testWlan() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/wlan.pcap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 39)
		assert(this.ipAddressTotal == 1520)
		assert(source.packetCount == 1895)
	}
	
	// TODO this is the per packet linktype and is currently unsupported
//	@Test
//	public void testHttp() {
//		Logger.getRootLogger().setLevel(Level.INFO)
//		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/Http.cap", this.pcapProperties)
//		source.ingestWithThreadHandler(this.accumulatorActor)
//		assert(this.ipAddressSet.size() == 39)
//		assert(this.ipAddressTotal == 1520)
//		assert(source.packetCount == 1895)
//	}
	
	@Test
	public void testJpegsHttp() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/http_witp_jpegs.cap", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 4)
		assert(this.ipAddressTotal == 478)
		assert(source.packetCount == 483)
	}
	
	@Test
	public void testDHCPBigEndian() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/dhcp_big_endian.pcapng", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 4)
		assert(this.ipAddressTotal == 4)
		assert(source.packetCount == 4)
	}
	
	@Test
	public void testDHCPLittleEndian() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/dhcp_little_endian.pcapng", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 4)
		assert(this.ipAddressTotal == 4)
		assert(source.packetCount == 4)
	}
	
	@Test
	public void testDHCP() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler source = new PcapBufferHandler("src/test/resources/dhcp.pcapng", this.pcapProperties)
		source.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 4)
		assert(this.ipAddressTotal == 4)
		assert(source.packetCount == 4)
	}
	
	@Test
	public void testManyInterfaces() {
		Logger.getRootLogger().setLevel(Level.INFO)
		PcapBufferHandler pbh = new PcapBufferHandler("src/test/resources/many_interfaces.pcapng", this.pcapProperties)
		pbh.ingestWithThreadHandler(this.accumulatorActor)
		assert(this.ipAddressSet.size() == 8)
		assert(this.ipAddressTotal == 62)
		assert(pbh.packetCount == 64)
	}

}
