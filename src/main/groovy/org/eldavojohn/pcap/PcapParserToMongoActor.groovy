package org.eldavojohn.pcap

import static groovyx.gpars.actor.Actors.*

import org.bson.Document
import org.bson.conversions.Bson
import org.eldavojohn.pcap.configuration.PcapConfigurationAndRegistry
import org.eldavojohn.pcap.events.TcpEvent
import org.eldavojohn.pcap.events.UdpEvent
import org.eldavojohn.pcap.io.PcapBufferHandler

import com.mongodb.BasicDBObject
import com.mongodb.MongoClient
import com.mongodb.client.MongoCollection
import com.mongodb.client.MongoDatabase
import com.mongodb.client.model.Filters
import com.mongodb.client.model.IndexOptions
import com.mongodb.client.model.UpdateOptions

import groovy.util.logging.Log4j

@Log4j
class PcapParserToMongoActor {
	public static void main(String[] args) {
		MongoClient mongoClient = new MongoClient('localhost:27017')
		MongoDatabase database = mongoClient.getDatabase("pcap")
		UpdateOptions options = new UpdateOptions().upsert(true)
		MongoCollection<Document> coll = database.getCollection("devices")
		coll.createIndex(new BasicDBObject("mac",1), new IndexOptions().unique(true))
		MongoCollection<Document> ipColl = database.getCollection("ips")
		ipColl.createIndex(new BasicDBObject("ip",1), new IndexOptions().unique(true))
		MongoCollection<Document> websiteColl = database.getCollection("websites")
		websiteColl.createIndex(new BasicDBObject("domain",1), new IndexOptions().unique(true))
		MongoCollection<Document> bootpColl = database.getCollection("bootp")
		bootpColl.createIndex(new BasicDBObject("name",1), new IndexOptions().unique(true))
		PcapConfigurationAndRegistry pcapProperties = new PcapConfigurationAndRegistry(PcapConstants.PROPERTIES_LOCATION)
		def pcapFileName = "src/test/resources/promiscuous-airport-2.pcap"
		log.info "Beginning processing of ${pcapFileName} at ${new Date()}"
		PcapBufferHandler source = new PcapBufferHandler(pcapFileName, pcapProperties.config)
		Bson filter
		Bson update
		final def mongodbActor = actor {
			loop {
				react { pcapEvent ->
					filter = Filters.eq("mac", pcapEvent.srcMacAddress)
					update = new Document('$set', new Document().append("count", 1))
					coll.updateOne(filter, update, options)
					filter = Filters.eq("mac", pcapEvent.dstMacAddress)
					update = new Document('$set', new Document().append("count", 1))
					coll.updateOne(filter, update, options)
					filter = Filters.eq("ip", pcapEvent.srcIpAddress)
					update = new Document('$set', new Document().append("count", 1))
					ipColl.updateOne(filter, update, options)
					filter = Filters.eq("ip", pcapEvent.dstIpAddress)
					update = new Document('$set', new Document().append("count", 1))
					ipColl.updateOne(filter, update, options)
					if(pcapEvent.subEvents) {
						pcapEvent.subEvents.each { subevent ->
							subevent.subEvents.each { udportcpevent ->
								if(udportcpevent && udportcpevent.properties.containsKey('queryDomains')) {
									udportcpevent['queryDomains'].each { dnsDomain ->
										filter = Filters.eq("domain", dnsDomain.toString())
										update = new Document('$set', new Document().append("count", 1))
										websiteColl.updateOne(filter, update, options)
									}
								}
								if(udportcpevent && udportcpevent.properties.containsKey('bootpName')) {
									filter = Filters.eq("name", udportcpevent['bootpName'].toString())
									update = new Document('$set', new Document().append("count", 1))
									bootpColl.updateOne(filter, update, options)
								}
							}
						}
					}
				}
			}
		}
		source.ingest(mongodbActor)
		// source.ingestWithThreadHandler(console)
		if(!source.keepReading) {
			log.info "Completed processing of ${pcapFileName} at ${new Date()}"
		}
	}

}
