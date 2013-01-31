package p3.hadoop.common.pcap.lib;

public class NewPcapRec{
	public static final int MAX_PACKET_LEN = 1518;	
	public static final int IP_PROTO = 0x0800;		
	public static final int IPV4 = 0x40;		
	public static final int UDP = 17;	
	public static final int TCP = 6;	
	public static final int ICMP = 1;		
	
	/* ETHERNET FRAME */
	public static final int POS_ETHEADER = 16;
	public static final int POS_ETH_TYPE = 28;
	public static final int LEN_ETH_TYPE = 2;

	/* IP PACKET */
	public static final int POS_IPHDR= 30;
	public static final int POS_IP_VER = 0;	
	public static final int LEN_IP_VER = 1;
	public static final int POS_IP_HLEN = 0;	
	public static final int LEN_IP_HLEN = 1;
	public static final int POS_IP_ST = 1;	
	public static final int LEN_IP_ST = 1;
	public static final int POS_IP_TLEN = 2;	
	public static final int LEN_IP_TLEN = 2;
	public static final int POS_IP_IDEN = 4;	
	public static final int LEN_IP_IDEN = 2;
	public static final int POS_IP_FLAGS = 6;	
	public static final int LEN_IP_FLAGS = 1;
	public static final int POS_IP_FO = 6;	
	public static final int LEN_IP_FO = 2;
	public static final int POS_IP_TTL = 8;	
	public static final int LEN_IP_TTL = 1;
	public static final int POS_IP_PROTO = 9;	
	public static final int LEN_IP_PROTO = 1;
	public static final int POS_IP_CS = 10;	
	public static final int LEN_IP_CS = 2;
	public static final int POS_IP_SIP = 12;	
	public static final int LEN_IP_SIP = 4;
	public static final int POS_IP_DIP = 16;	
	public static final int LEN_IP_DIP = 4;
	public static final int POS_IP_OP = 20;	
	public static final int LEN_IP_OP = 4;
	
	/* TCP Segment */
	public static int POS_TCP_SPORT = 0;	
	public static int POS_TCP_DPORT = 2;	
	public static int POS_TCP_SEQ = 4;
	public static int POS_TCP_ACK = 8;	
	public static int POS_TCP_OFFSET = 12;
	public static int POS_TCP_RSV = 12;
	public static int POS_TCP_CTRL = 13;	
	public static int POS_TCP_WIN = 14;	
	public static int POS_TCP_CSUM = 16;
	public static int POS_TCP_URG = 18;	
	public static int POS_TCP_PAD = 20;	
	public static int POS_TCP_OPTION = 20;	
	
	/* UDP Segment */
	public static int POS_UDP_SPORT = 0;	
	public static int POS_UDP_DPORT = 2;	
	public static int POS_UDP_TLEN = 4;
	public static int POS_UDP_CSUM = 6;	
	
	//-----------------------------------//
	public static final int LEN_VAL1 = 4;	
	public static final int POS_VAL = 2;
	
	public static final int LEN_VAL2 = LEN_VAL1*2;
	public static final int LEN_VAL3 = LEN_VAL1*3;	
	public static final int POS_V_BC = POS_VAL;		
	public static final int POS_V_PC = LEN_VAL1+POS_VAL;
//	public static final int POS_V_FC = LEN_VAL2+POS_VAL;
	
	/* DNS & NetBOIS Name Service */
	public static final int POS_NS_TRANSID = 0;
	public static final int POS_NS_FLAGS = 2;
	public static final int POS_NS_QUERY = 4;
	public static final int POS_NS_ANSWER = 6;
	
}
