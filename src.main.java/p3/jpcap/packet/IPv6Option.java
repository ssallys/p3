package p3.jpcap.packet;

import java.net.InetAddress;

/** This class represents IPv6 option headers. */
public class IPv6Option implements java.io.Serializable{
	private static final long serialVersionUID = 4027393032973499183L;
	
	/** Hop by hop option */
	public static final byte HOP_BY_HOP_OPTION=0;
	/** Routing option */
	public static final byte ROUTING_OPTION=43;
	/** Fragment option */
	public static final byte FRAGMENT_OPTION=44;
	/** Security payload option */
	public static final byte ESP_OPTION=50;
	/** Authentication option */
	public static final byte AH_OPTION=51;
	/** No next option header */
	public static final byte NONE_OPTION=59;
	/** Destination option */
	public static final byte DESTINATION_OPTION=60;

	/** Type */
	public byte type;
	/** Next header */
	public byte next_header;
	/** Header length */
	public byte hlen;

	/** Option */
	public byte[] option;

	/** Routing type (Routing option) */
	public byte routing_type;
	/** Hop number left (Routing option) */
	public byte hop_left;
	/** Route addresses (Routing option) */
	public InetAddress[] addrs;

	/** Offset (Fragment option) */
	public short offset;
	/** More flag (fragment option) */
	public boolean m_flag;
	/** Identification (fragment option) */
	public int identification;

	/** SPI (AH option) */
	public int spi;
	/** Sequence number (AH option) */
	public int sequence;

	void setValue(byte type,byte next,byte hlen){
		this.type=type;
		this.next_header=next;
		this.hlen=hlen;
	}

	void setOptionData(byte[] option){
		this.option=option;
	}

	void setRoutingOption(byte type,byte left,byte[][] addrs){
		this.routing_type=type;
		this.hop_left=left;
		this.addrs=new InetAddress[addrs.length];
		for(int i=0;i<addrs.length;i++){
			try{
				this.addrs[i]=InetAddress.getByAddress(addrs[i]);
			}catch(java.net.UnknownHostException e){}
		}
	}

	void setFragmentOption(short offset,boolean m,int ident){
		this.offset=offset;
		this.m_flag=m;
		this.identification=ident;
	}

	void setAHOption(int spi,int seq){
		this.spi=spi;
		this.sequence=seq;
	}
}
