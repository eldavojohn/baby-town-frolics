package org.eldavojohn.pcap.configuration

import static org.junit.Assert.*

import org.junit.Before
import org.junit.Test

class MacReferenceTest {

	private MacReference mair
	
	@Before
	public void setUp() throws Exception {
		this.mair = new MacReference()
		this.mair.loadOuisFromFile()
		this.mair.loadIabOuisFromFile('src/main/resources/ieeeIab.txt')
		this.mair.loadIabOuisFromFile('src/main/resources/ieeeOui36.txt')
	}

	@Test
	public void testOuiLoading() {
		MacAddressBlock mab = this.mair.ouis.get("2C3033")
		MacOwner mo = mab.owners.getAt(0)
		assert(mo.name == "NETGEAR")
		assert(mo.mailingName == "NETGEAR")
		assert(mo.addressLineOne == "350 East Plumeria Drive")
		assert(mo.city == "San Jose")
		assert(mo.state == "CA") // for some reason these come up as null in the original file so make sure it's hand changed!
		assert(mo.zipCode == "95134")
		assert(mo.countryCode == "US")
		assert(this.mair.ouis.size() == 22000)
		mab = this.mair.ouis.get("40D855") //40-D8-55 
		assert(mab.iabOwners.keySet().size() == 487)
		mab = this.mair.ouis.get("0050C2") //00-50-C2
		assert(mab.iabOwners.keySet().size() == 4088)
		mab = this.mair.ouis.get("00A0C6")
	}
	
	@Test
	public void testOuiRetrieval() {
		assert(null == this.mair.retrieveMacData("34:44"))
		assert(this.mair.retrieveMacData("2C:30:33").owners.getAt(0).name == "NETGEAR")
		assert(this.mair.retrieveMacData("2C-30-33").owners.getAt(0).name == "NETGEAR")
		assert(this.mair.retrieveMacData("40-D8-55-13-0F-FF").owners.getAt(0).name != "EMAC, Inc.")
		assert(this.mair.retrieveMacData("40-D8-55-13-10-00").owners.getAt(0).name == "EMAC, Inc.")
		assert(this.mair.retrieveMacData("40-D8-55-13-10-01").owners.getAt(0).name == "EMAC, Inc.")
		assert(this.mair.retrieveMacData("40-D8-55-13-1F-FF").owners.getAt(0).name == "EMAC, Inc.")
		assert(this.mair.retrieveMacData("40-D8-55-13-20-00").owners.getAt(0).name != "EMAC, Inc.")
	}

}
