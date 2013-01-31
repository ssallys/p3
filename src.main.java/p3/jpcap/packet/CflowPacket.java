package p3.jpcap.packet;

/** This class represents UDP packet. */
public class CflowPacket extends UDPPacket
{
	public short fheader;
	public short fcount;
	public int fsys_uptime;
	public int unix_secs;
	public int unix_nsecs;	
	public int flow_sequence;
	public byte engine_type;
	public byte engine_id;
	public short sampling_interval;

	private static final long serialVersionUID = 5419011849692338454L;
	
	public CflowPacket(int src_port, int dst_port) {
		super(src_port, dst_port);
		// TODO Auto-generated constructor stub
	} 
	void setValue(short fheader, short fcount, int fsys_uptime, int unix_secs,int unix_nsecs,int flow_sequence,byte engine_type, byte engine_id,short sampling_interval){
		this.fheader = fheader;              
		this.fheader = fheader;               
		this.fcount =  fcount;                  
		this.fsys_uptime=fsys_uptime;           
		this.unix_secs=unix_secs;              
		this.unix_nsecs=unix_nsecs;	          
		this.flow_sequence= flow_sequence;     
		this.engine_type=engine_type;           
		this.engine_id= engine_id;               
		this.sampling_interval=sampling_interval;
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
