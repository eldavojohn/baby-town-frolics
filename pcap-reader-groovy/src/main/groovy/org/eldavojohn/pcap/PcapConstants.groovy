package org.eldavojohn.pcap

class PcapConstants {
	static final String PROPERTIES_LOCATION = "src/main/resources/pcap.properties"
	final static int BYTE_PAGE_SIZE = 1024*1024 // read 1 MB into memory at a time
	
	final static byte[] CH_HTTP = [72, 84, 84, 80]
	final static byte[] CH_GET = [71, 69, 84]
	final static byte[] CH_HEAD = [72, 69, 65, 68]
	final static byte[] CH_POST = [80, 79, 83, 84]
	final static byte[] CH_PUT = [80, 85, 84]
	final static byte[] CH_DELETE = [68, 69, 76, 69, 84, 69]
	final static byte[] CH_TRACE = [84, 82, 65, 67, 69]
	final static byte[] CH_OPTIONS = [79, 80, 84, 73, 79, 78, 83]
	final static byte[] CH_CONNECT = [67, 79, 78, 78, 69, 67, 84]
	final static byte[] CH_PATCH = [80, 65, 84, 67, 72]

	final static byte[] libpcapFileStart = [-95, -78, -61, -44]
	final static byte[] libpcapFileStartReverse = [-44, -61, -78, -95]

	final static byte[] ngPcapFileStart = [10, 13, 13, 10]
	final static byte[] ngPcapFileIdReverse = [77, 60, 43, 26]
	final static byte[] interfaceBlock = [0, 0, 0, 1]
	final static byte[] nameResolutionBlock = [0, 0, 0, 4]
	final static byte[] interfaceStatsBlock = [0, 0, 0, 5]
	final static byte[] enhancedPacketBlock = [0, 0, 0, 6]
	final static byte[] interfaceBlockReverse = [1, 0, 0, 0]
	final static byte[] nameResolutionBlockReverse = [4, 0, 0, 0]
	final static byte[] interfaceStatsBlockReverse = [5, 0, 0, 0]
	final static byte[] enhancedPacketBlockReverse = [6, 0, 0, 0]
}
