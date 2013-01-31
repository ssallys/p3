package p3.jpcap.packet;

/** This class represents Ethernet packet. */
public class EthernetPacket extends DatalinkPacket
{
	private static final long serialVersionUID = 817080364073605844L;

	/** Destination MAC address (6byte) */
	public byte[] dst_mac;

	/** Source MAC address (6byte) */
	public byte[] src_mac;

	/** Frame type */
	public short frametype;
	/** PUP protocol */
	public static final short ETHERTYPE_PUP = 0x0200;
	/** IP protocol */
	public static final short ETHERTYPE_IP  = 0x0800;
	/** Addr. resolution protocol */
	public static final short ETHERTYPE_ARP = 0x0806;  
	/** reverse Addr. resolution protocol */
	public static final short ETHERTYPE_REVARP = (short)0x8035;
	/** IEEE 802.1Q VLAN tagging */
	public static final short ETHERTYPE_VLAN = (short)0x8100;
	/** IPv6 */
	public static final short ETHERTYPE_IPV6 = (short)0x86dd;  
	/** used to test interfaces */
	public static final short ETHERTYPE_LOOPBACK = (short)0x9000;  

	void setValue(byte[] dst,byte[] src,short frame){
		this.dst_mac=dst;
		this.src_mac=src;
		this.frametype=frame;
	}

	/** Returns the MAC address of the source.
         * @return MAC address of the source
         */
	public String getSourceAddress(){
		char[] src=new char[17];

		for(int i=0;i<5;i++){
			src[i*3]=hexUpperChar(src_mac[i]);
			src[i*3+1]=hexLowerChar(src_mac[i]);
			src[i*3+2]=':';
		}
		src[15]=hexUpperChar(src_mac[5]);
		src[16]=hexLowerChar(src_mac[5]);

		return new String(src);
	}

	/** Returns the MAC address of the destination.
         * @return MAC address of the destination
         */
	public String getDestinationAddress(){
		char[] dst=new char[17];

		for(int i=0;i<5;i++){
			dst[i*3]=hexUpperChar(dst_mac[i]);
			dst[i*3+1]=hexLowerChar(dst_mac[i]);
			dst[i*3+2]=':';
		}
		dst[15]=hexUpperChar(dst_mac[5]);
		dst[16]=hexLowerChar(dst_mac[5]);

		return new String(dst);
	}

	/** Returns a string representation of this Ethernet packet.<BR>
         * <BR>
         * Format: Fsrc_mac -> dst_mac (frametype)
         * @return a string representation of this Ethernet packet
         */
	public String toString(){


		return super.toString()+" "+getSourceAddress()+"->"+
			getDestinationAddress()+" ("+frametype+")";
	}

	private char hexUpperChar(byte b){
		b=(byte)((b>>4)&0xf);
		if(b==0) return '0';
		else if(b<10) return (char)('0'+b);
		else return (char)('a'+b-10);
	}

	private char hexLowerChar(byte b){
		b=(byte)(b&0xf);
		if(b==0) return '0';
		else if(b<10) return (char)('0'+b);
		else return (char)('a'+b-10);
	}
}
