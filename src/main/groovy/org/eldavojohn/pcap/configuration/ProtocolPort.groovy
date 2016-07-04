package org.eldavojohn.pcap.configuration

class ProtocolPort {
	String serviceName,portNumber,transportProtocol,description,assignee,contact,registrationDate,modificationDate,reference,serviceCode,knownUnauthorizedUses,assignmentNotes

	def ProtocolPort(serviceName,portNumber,transportProtocol,description,assignee,contact,registrationDate,modificationDate,reference,serviceCode,knownUnauthorizedUses,assignmentNotes) {
		this.serviceName = serviceName
		this.portNumber = portNumber
		this.transportProtocol = transportProtocol
		this.description = description
		this.assignee = assignee
		this.contact = contact
		this.registrationDate = registrationDate
		this.modificationDate = modificationDate
		this.reference = reference
		this.serviceCode = serviceCode
		this.knownUnauthorizedUses = knownUnauthorizedUses
		this.assignmentNotes = assignmentNotes
	}
}
