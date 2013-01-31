package p3.jpcap.packet;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** This class represents ARP/RARP packet. */
public class ARPPacket extends Packet
{
	private static final long serialVersionUID = 3271911802471786372L;
	
	/** Hardware type */
	public short hardtype;
	/** Hardware type: Ethernet */
	public static final short HARDTYPE_ETHER=1;
	/** Hardware type: Token ring */
	public static final short HARDTYPE_IEEE802=6;
	/** Hardware type: Frame relay */
	public static final short HARDTYPE_FRAMERELAY=15;

	/** Protocol type */
	public short prototype;
	/** Protocol type: IP */
	public static final short PROTOTYPE_IP=2048;

	/** Hardware address length */
	public short hlen;

	/** Protocol address length */
	public short plen;

	/** Operation */
	public short operation;
	/** ARP request */
	public static final short ARP_REQUEST=1;
	/** ARP reply */
	public static final short ARP_REPLY=2;
	/** Reverse ARP request */
	public static final short RARP_REQUEST=3;
	/** Reverse ARP reply */
	public static final short RARP_REPLY=4;
	/** Identify peer request */
	public static final short INV_REQUEST=8;
	/** Identify peer response */
	public static final short INV_REPLY=9;


	/** Sender hardware address */
	public byte[] sender_hardaddr;
	/** Sender protocol address */
	public byte[] sender_protoaddr;
	/** Target hardware address */
	public byte[] target_hardaddr;
	/** Target protocol address */
	public byte[] target_protoaddr;

	void setValue(short hardtype,short prototype,short hlen,short plen,
			 short operation,byte[] sha,byte[] spa,byte[] tha,byte[] tpa){
		this.hardtype=hardtype;
		this.prototype=prototype;
		this.hlen=hlen;this.plen=plen;
		this.operation=operation;
		sender_hardaddr=sha;
		sender_protoaddr=spa;
		target_hardaddr=tha;
		target_protoaddr=tpa;
	}

	/** Returns the hardware address (MAC address) of the sender.
         * @return Hardware address of the sender
         */
	public Object getSenderHardwareAddress(){
		switch(hardtype){
			case HARDTYPE_ETHER:
				char[] adr=new char[17];

				for(int i=0;i<5;i++){
					adr[i*3]=hexUpperChar(sender_hardaddr[i]);
					adr[i*3+1]=hexLowerChar(sender_hardaddr[i]);
					adr[i*3+2]=':';
				}
				adr[15]=hexUpperChar(sender_hardaddr[5]);
				adr[16]=hexLowerChar(sender_hardaddr[5]);

				return new String(adr);
			default:
				return "Unknown Protocol";
		}
	}

	/** Returns the hardware address (MAC address) of the target.
         * @return Hardware address of the target
         */
	public Object getTargetHardwareAddress(){
		switch(hardtype){
			case HARDTYPE_ETHER:
				char[] adr=new char[17];

				for(int i=0;i<5;i++){
					adr[i*3]=hexUpperChar(target_hardaddr[i]);
					adr[i*3+1]=hexLowerChar(target_hardaddr[i]);
					adr[i*3+2]=':';
				}
				adr[15]=hexUpperChar(target_hardaddr[5]);
				adr[16]=hexLowerChar(target_hardaddr[5]);

				return new String(adr);
			default:
				return "Unknown Protocol";
		}
	}

	/** Returns the protocol address of the sender.
         * @return Protocol address of the sender
         */
	public Object getSenderProtocolAddress(){
		switch(prototype){
			case PROTOTYPE_IP:
				try {
					return InetAddress.getByAddress(sender_protoaddr);
				} catch (UnknownHostException e) {
					return "Unknown Address";
				}
			default:
				return "Unknown Protocol";
		}
	}
	
	/** Returns the protocol address of the target.
         * @return Protocol address of the target
         */
	public Object getTargetProtocolAddress(){
		switch(prototype){
			case PROTOTYPE_IP:
				try {
					return InetAddress.getByAddress(target_protoaddr);
				} catch (UnknownHostException e) {
					return "Unknown Address";
				}
			default:
				return "Unknown Protocol";
		}
	}

	/** Returns a string representation of this ARP/RARP packet.<BR>
         *
         * <BR>
         * Format: ARP(hardtype:prototype)
         * @return a string representation of this ARP/RARP packet
         */
	public String toString(){
		StringBuffer buf=new StringBuffer();
		
		switch(operation){
			case ARP_REQUEST: buf.append("ARP REQUEST ");break;
			case ARP_REPLY: buf.append("ARP REPLY ");break;
			case RARP_REQUEST: buf.append("RARP REQUEST ");break;
			case RARP_REPLY: buf.append("RARP REPLY ");break;
			case INV_REQUEST: buf.append("IDENTIFY REQUEST ");break;
			case INV_REPLY: buf.append("IDENTIFY REPLY ");break;
			default: buf.append("UNKNOWN ");break;
		}
		
		return buf.toString()+getSenderHardwareAddress()+"("+getSenderProtocolAddress()+") -> "+
		       getTargetHardwareAddress()+"("+getTargetProtocolAddress()+")";
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
