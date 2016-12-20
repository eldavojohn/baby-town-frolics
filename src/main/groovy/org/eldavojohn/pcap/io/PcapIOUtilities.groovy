package org.eldavojohn.pcap.io

class PcapIOUtilities {
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray()

	public static int little2big(int i) {
		return (i&0xff)<<24 | (i&0xff00)<<8 | (i&0xff0000)>>8 | (i>>24)&0xff;
	}

	public static String bytesToHex(bytes) {
		char[] hexChars = new char[bytes.size() * 2]
		for ( int j = 0; j < bytes.size(); j++ ) {
			int v = bytes[j] & 0xFF
			hexChars[j * 2] = hexArray[v >>> 4]
			hexChars[j * 2 + 1] = hexArray[v & 0x0F]
		}
		return new String(hexChars)
	}

	public static int bytesToInt(bytes) {
		int ret = 0
		for ( int j = 0; j < bytes.size(); j++ ) {
			ret = ret << 8
			ret = ret | (int)bytes[j] & 0xFF
		}
		return ret
	}

	public static bytesToIpAddress(bytes) {
		if(bytes.size() == 4) {
			StringBuffer str = new StringBuffer()
			str.append((bytes[0] & 0xFF) + ".")
			str.append((bytes[1] & 0xFF) + ".")
			str.append((bytes[2] & 0xFF) + ".")
			str.append((bytes[3] & 0xFF))
			return str
		} else {
			println "WARNING: incorrect number of bytes for ip address!"
			return bytes
		}
	}
	
	public static bytesToIpv6Address(bytes) {
		String address = PcapIOUtilities.bytesToHex(bytes)
		if(address.size() == 32) {
			def octetGroupMatcher = address =~ /[0-9a-fA-F]{4}/
			return octetGroupMatcher[0..7].join(":")
		} else {
			println "WARNING: incorrect number of bytes for ip address!"
			return bytes
		}
	}

	static padTo32(val) {
		if(val % 4 == 1) {
			return 3
		} else if(val % 4 == 2) {
			return 2
		} else if(val % 4 == 3) {
			return 1
		}
		return 0
	}

	static byteArrayToReadable(arr) {
		StringBuffer result = new StringBuffer()
		for(ch in arr) {
			if(Character.isDefined(ch) && !Character.isISOControl(ch)) {
				result.append((char )ch)
			}
		}
		return result
	}
	
	static byteArrayToDnsReadableWithDots(arr) {
		StringBuffer result = new StringBuffer()
		arr = arr[1..(arr.size() - 1)]
		for(ch in arr) {
			if(Character.isDefined(ch) && !Character.isISOControl(ch)) {
				result.append((char )ch)
			} else if(ch == 0x00) {
				return result
			} else {
				result.append('.')
			}
		}
		return result
	}
	
	static byteArrayToIpString(arr) {
		return Integer.toString(arr[0]) + '.' + Integer.toString(arr[1]) + '.' + Integer.toString(arr[2]) + '.' + Integer.toString(arr[3])
	}

	static byteArrayToRaw(arr) {
		StringBuffer result = new StringBuffer()
		for(ch in arr) {
			result.append((char )ch)
		}
		return result
	}

	static orderBytes(bytes, swap) {
		if(swap) {
			return bytes.reverse()
		} else {
			return bytes
		}
	}

	static retrieveWordFromIndex(arr, i, swap) {
		def k = i*4
		def g = k + 3
		if(swap) {
			return PcapIOUtilities.bytesToHex(arr[k..g].reverse())
		} else {
			return PcapIOUtilities.bytesToHex(arr[k..g])
		}
	}
}
