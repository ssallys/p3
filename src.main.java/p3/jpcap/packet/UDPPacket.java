package p3.jpcap.packet;

/** This class represents UDP packet. */
public class UDPPacket extends IPPacket
{
	private static final long serialVersionUID = -3170544240823207254L;
	
	/** Source port number */
	public int src_port;
	/** Destination port number */
	public int dst_port;
	/** packet length */
	public int length;
	
	/** Creates a UDP packet.
         * @param src_port source port number
         * @param dst_port destination port number
         */
	public UDPPacket(){};
	public UDPPacket(int src_port,int dst_port){
		this.src_port=src_port;
		this.dst_port=dst_port;
	}

	public void setValue(int src,int dst,int len){
		src_port=src;dst_port=dst;
		length=len;
	}
	
	/** Returns a string representation of this packet.<BR>
         *
         * <BR>
         * Format: src_port > dst_port
         * @return a string representation of this packet
         */
	public String toString(){
		return super.toString()+" UDP "+src_port+" > "+dst_port;
	}
}
