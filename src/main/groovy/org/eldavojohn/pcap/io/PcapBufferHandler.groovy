package org.eldavojohn.pcap.io

import static groovyx.gpars.actor.Actors.*
import groovy.util.logging.Log4j

import java.nio.ByteBuffer
import java.nio.channels.FileChannel

import org.eldavojohn.pcap.PcapConstants
import org.eldavojohn.pcap.application.CommunicationEventProcessor
import org.eldavojohn.pcap.configuration.MacReference
import org.eldavojohn.pcap.configuration.ProtocolPortReference
import org.eldavojohn.pcap.events.CommunicationEvent
import org.eldavojohn.pcap.transport.TcpSessionStore

@Log4j
class PcapBufferHandler {

	private boolean swapEndian
	private String fileType
	private String fileName

	private FileChannel inChannel
	private ByteBuffer byteBuf
	private int position
	private byteArray
	private keepReading
	private fileEmpty

	private packetCount = 0
	
	private linkType = 0

	private TcpSessionStore tcpSessionStore = new TcpSessionStore()
	private MacReference macReference = new MacReference()
	private ProtocolPortReference ppr = new ProtocolPortReference()
	
	private Thread threadHandler
	
	// TODO if protocols like UDP and TCP are disabled, we shouldn't even parse them
	private config

	// TODO probably should abstract the byte layouts to some sort of structure
	// for better readability/maintainability/future formats

	def ingestWithThreadHandler(actor=null) {
		ingest(actor)
	}
	
	def isFinished() {
		return !this.keepReading
	}

	def PcapBufferHandler(String filename, pcapProperties) {
		this.fileName = filename
		this.config = pcapProperties
		
		this.macReference = new MacReference()
		this.macReference.loadOuisFromFile('src/main/resources/ieeeOui.txt')
		this.macReference.loadIabOuisFromFile('src/main/resources/ieeeIab.txt')
		this.macReference.loadIabOuisFromFile('src/main/resources/ieeeOui36.txt')
	}
	
	synchronized ingest(userActor=null) {
		byteBuf = ByteBuffer.allocate(PcapConstants.BYTE_PAGE_SIZE)
		this.position = 0
		File pcapFile = new File(this.fileName)
		FileInputStream inFile = null
		try {
			inFile = new FileInputStream(pcapFile)
		} catch (FileNotFoundException e) {
			log.error "Could not read or find file ${this.fileName}", e
		}
		inChannel = inFile.getChannel()
		this.swapEndian = false
		ByteBuffer tasteBuf = ByteBuffer.allocate(12)
		try {
			inChannel.read(tasteBuf)
			def bytearray = tasteBuf.array()
			if(bytearray[0..3] == PcapConstants.ngPcapFileStart) {
				this.fileType = "ng"
				if(bytearray[8..11] == PcapConstants.ngPcapFileIdReverse) {
					// endian difference
					this.swapEndian = true
				}
			} else if (bytearray[0..3] == PcapConstants.libpcapFileStart || bytearray[0..3] == PcapConstants.libpcapFileStartReverse) {
				this.fileType = "libpcap"
				if(bytearray[0..3] == PcapConstants.libpcapFileStartReverse) {
					// endian difference
					this.swapEndian = true
				}

			} else {
				log.error "File: ${this.fileName}, did not recognize filetype with magic bytes: " + PcapIOUtilities.bytesToHex(bytearray)
			}
			tasteBuf.clear()
			inFile.close()
		} catch (IOException e) {
			log.error "IO problem with file ${this.fileName}", e
		}
		inFile = null
		try {
			inFile = new FileInputStream(pcapFile)
		} catch (FileNotFoundException e) {
			log.error "Could not read or find file ${this.fileName}", e
		}
		this.inChannel = inFile.getChannel()
		readPage()
		this.keepReading = true
		this.fileEmpty = false
		while(this.keepReading) {
			if (this.fileType == "ng") {
				readNextGenerationBlockData(userActor)
			} else if (this.fileType == "libpcap") {
				readLibPcapBlockData(userActor)
			} else {
				log.warn "Unrecognzied file type in file ${this.fileName}"
				// unkown file type
			}
		}
	}

	def readLibPcapBlockData(userActor=null) {
		def header = getNextNBytes(4)
		if(!this.keepReading) {
			return 0
		}
		def blockSize = 0
		def blockBytes
		if(header == PcapConstants.libpcapFileStartReverse || header == PcapConstants.libpcapFileStart) {
			def versions = getNextNBytes(4)
			def thisZone = getNextNBytes(4)
			def sigFlags = getNextNBytes(4)
			def headerSize = getNextNBytes(4)
			def networks = getNextNBytes(4)
			try {
				this.linkType = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(networks, this.swapEndian)), 16)
				blockSize = Integer.parseInt(PcapIOUtilities.orderBytes(PcapIOUtilities.bytesToHex(headerSize), this.swapEndian), 16)
			} catch (Exception e) {
				this.keepReading = false
				log.error "Problem with packet block! " + Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(header, this.swapEndian)), 16), e
			}
			log.info "global header block of size " + blockSize
		} else {
			def timeStampSeconds, timeStampsMicroSeconds, packetLength
			try {
				timeStampSeconds = Long.parseLong(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(header, this.swapEndian)), 16)
				timeStampsMicroSeconds = Long.parseLong(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian)), 16)
				packetLength = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian)), 16)
				def originalPacketLength = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian)), 16)
				blockSize = packetLength
			} catch (Exception e) {
				this.keepReading = false
				log.error "Problem with packet block!", e
			}
			if(blockSize > 0) {
				log.info "packet block of length " + blockSize
				log.info "packet block ${++packetCount}"
				blockBytes = getNextNBytes(blockSize)
				CommunicationEvent finalStoreEvent = LibPCapFormatUtils.processLibPcapPacketBlock(blockBytes, (long )(timeStampSeconds * 1000 + timeStampsMicroSeconds / 1000), packetLength, blockSize, tcpSessionStore, this.config, this.swapEndian, this.linkType, keepReading)
				if(finalStoreEvent != null) {
					CommunicationEventProcessor.processFinalEvent(finalStoreEvent, config, userActor)
				}
			} else {
				this.keepReading = false
			}
		}
		return true
	}

	def readNextGenerationBlockData(userActor=null) {
		def header = getNextNBytes(4)
		if(!this.keepReading) {
			return 0
		}
		def headerSize = getNextNBytes(4)
		def blockSize = 0
		def blockBytes
		try {
			blockSize = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(headerSize, this.swapEndian)), 16)
		} catch (Exception e) {
			this.keepReading = false
			log.error "Problem with packet block!", e
		}

		if(header == PcapConstants.enhancedPacketBlockReverse || header == PcapConstants.enhancedPacketBlock) {
			log.info "packet block ${++packetCount}"
			blockBytes = getNextNBytes(blockSize - 12)
			try {
				def intblock = PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian))
				if(blockSize != Integer.parseInt(intblock, 16)) {
					log.error "WARNING: Wrong total bytes at end of block!"
				}
				def padding = PcapIOUtilities.padTo32(blockSize)
				if(padding > 0) {
					getNextNBytes(padding)
				}
				// this.threadHandler = new Thread({ ->
				CommunicationEvent finalStoreEvent = NextGenerationFormatUtils.processPacketBlock(blockBytes, blockSize, this.swapEndian, this.config, tcpSessionStore)
				if(finalStoreEvent != null) {
					CommunicationEventProcessor.processFinalEvent(finalStoreEvent, config, userActor)
				}
				// }).start()
			} catch(Exception e) {
				log.error "Problem with packet block!", e
			}
		} else if(header == PcapConstants.interfaceBlockReverse || header == PcapConstants.interfaceBlock) {
			log.info "interface block"
			blockBytes = getNextNBytes(blockSize - 12)
			if(blockSize != Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian)), 16)) {
				log.error "WARNING: Wrong total bytes at end of block!"
			}
			def padding = PcapIOUtilities.padTo32(blockSize)
			if(padding > 0) {
				getNextNBytes(padding)
			}
			NextGenerationFormatUtils.processInterfaceBlock(blockBytes, blockSize, this.swapEndian)
		} else if(header == PcapConstants.ngPcapFileStart) {
			blockBytes = getNextNBytes(blockSize - 12)
			def test = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian)), 16)
			if(blockSize != test) {
				log.error "WARNING: Wrong total bytes at end of block!"
			}
			def padding = PcapIOUtilities.padTo32(blockSize)
			if(padding > 0) {
				getNextNBytes(padding)
			}
			NextGenerationFormatUtils.processSectionBlock(blockBytes, this.swapEndian)
		} else if(header == PcapConstants.interfaceStatsBlockReverse || header == PcapConstants.interfaceStatsBlock) {
			blockBytes = getNextNBytes(blockSize - 12)
			def test = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian)), 16)
			if(blockSize != test) {
				log.error "WARNING: Wrong total bytes at end of block!"
			}
			def padding = PcapIOUtilities.padTo32(blockSize)
			if(padding > 0) {
				getNextNBytes(padding)
			}
			NextGenerationFormatUtils.processInterfaceStatsBlock(blockBytes, this.swapEndian)
		} else if(header == PcapConstants.nameResolutionBlock || header == PcapConstants.nameResolutionBlockReverse) {
			blockBytes = getNextNBytes(blockSize - 12)
			def test = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(getNextNBytes(4), this.swapEndian)), 16)
			if(blockSize != test) {
				log.error "WARNING: Wrong total bytes at end of block!"
			}
			def padding = PcapIOUtilities.padTo32(blockSize)
			if(padding > 0) {
				getNextNBytes(padding)
			}
			NextGenerationFormatUtils.processNameResolutionBlock(blockBytes, this.swapEndian)
		} else {
			log.error header
			blockBytes = getNextNBytes(blockSize - 8)
			log.error "WARNING: UNRECOGNIZED PACKET TYPE: " + PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(header, this.swapEndian)) + " of size " + blockSize
			if(header == [0, 0, 0, 0] && PcapIOUtilities.bytesToInt(PcapIOUtilities.orderBytes(header, this.swapEndian)) == 0) {
				this.keepReading = false
			}
		}
		return true
	}

	// TODO this doesn't work but it should according to the spec
	static processPacketOptions(blockData, optionPosition) {
		def optionEnd = false
		def optionLength = 0
		def opts = [:]
		while (!optionEnd) {
			//			def otype = PcapIOUtilities.orderBytes(blockData[optionPosition..(optionPosition+1)])
			//			optionLength = Integer.parseInt(PcapIOUtilities.bytesToHex(PcapIOUtilities.orderBytes(blockData[(optionPosition + 2)..(optionPosition + 3)])), 16)
			//			optionPosition += 4
			//			if(otype == [0, 0] && optionLength == 0) {
			//				optionEnd = true
			//			} else {
			//				opts.put(PcapIOUtilities.bytesToHex(otype), PcapIOUtilities.byteArrayToReadable(blockData[optionPosition..(optionPosition+optionLength)]))
			//				optionLength += PcapIOUtilities.padTo32(optionLength)
			//				optionPosition += optionLength
			//			}
			optionEnd = true
		}
		return opts
	}

	def getNextNBytes(n) {
		def oldPosition = this.position
		def remainder = PcapConstants.BYTE_PAGE_SIZE - this.position
		if(remainder <= n) {
			def chunk = this.byteArray[this.position..(PcapConstants.BYTE_PAGE_SIZE - 1)]
			def getMoreBytes = true
			while(getMoreBytes && !this.fileEmpty) {
				readPage()
				if(n >= chunk.size() + PcapConstants.BYTE_PAGE_SIZE) {
					chunk.addAll(this.byteArray)
				} else {
					this.position = PcapConstants.BYTE_PAGE_SIZE - (chunk.size() + PcapConstants.BYTE_PAGE_SIZE - n)
					if(this.position > 0 && this.byteArray.size() >= this.position) {
						chunk.addAll(this.byteArray[0..(this.position - 1)])
					} else if(this.position > 0 && this.byteArray.size() < this.position && this.byteArray.size() > 0) {
						log.warn "Getting the next bytes failed due to lack of bytes in the buffer array."
						chunk.addAll(this.byteArray[0..(this.byteArray.size() - 1)])
						this.keepReading = false
					} else if(this.byteArray.size() == 0) {
						log.warn "Getting the next bytes failed due to no avialable bytes in the buffer array."
						this.keepReading = false
					}
					getMoreBytes = false
				}
			}
			if(chunk.size() != n) {
				// this must be the last packet and it's coming up short
				log.info "Last packet detected, ${packetCount} total packets read."
			}
			return chunk
		} else {
			this.position += n
			if(this.byteArray.size() < this.position - 1) {
				// End of File
				return new ArrayList<Byte>()
			}
			return this.byteArray[oldPosition..(this.position - 1)]
		}
	}

	def readPage() {
		try {
			int readResult = this.inChannel.read(byteBuf)
			if(readResult <= 0) {
				this.fileEmpty = true
				this.byteArray = new ArrayList<Byte>()
				byteBuf.clear()
				return
			}
			this.byteArray = byteBuf.array() // new ArrayList<Byte>(byteBuf.array())
			byteBuf.clear()
		} catch (IOException e) {
			log.error "Error reading new bytes into bytebuf ... ", e
		}
	}
}
