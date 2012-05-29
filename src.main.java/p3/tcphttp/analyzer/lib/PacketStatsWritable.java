package p3.tcphttp.analyzer.lib;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.hadoop.record.Buffer;

import p3.common.lib.BinaryUtils;
import p3.common.lib.Bytes;
import p3.common.lib.EZBytes;
import p3.hadoop.common.pcap.lib.NewPcapRec;
import p3.jpcap.packet.EthernetPacket;
import p3.jpcap.packet.IPPacket;

/** This class represents TCP packet. */
//public class PacketStatWritable extends IPPacket implements WritableComparable<PacketStatWritable>
public class PacketStatsWritable extends org.apache.hadoop.record.Record
{
	public static final int C2S = 1;
	public static final int S2C = -1;
	public static final int NONE = 0;
	public static final int PCAPHEADER_LEN = 16;	
	public static final int MIN_PKT_SIZE = 42;
	
	protected static final org.apache.hadoop.record.meta.RecordTypeInfo _rio_recTypeInfo;
	protected static org.apache.hadoop.record.meta.RecordTypeInfo _rio_rtiFilter;
	protected static int[] _rio_rtiFilterFields;
	static {
		_rio_recTypeInfo = new org.apache.hadoop.record.meta.RecordTypeInfo("TcpStats");
		
		_rio_recTypeInfo.addField("src_ip", org.apache.hadoop.record.meta.TypeID.StringTypeID);
		_rio_recTypeInfo.addField("dst_ip", org.apache.hadoop.record.meta.TypeID.StringTypeID);
		_rio_recTypeInfo.addField("src_port", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("dst_port", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("packets", org.apache.hadoop.record.meta.TypeID.LongTypeID);//
		_rio_recTypeInfo.addField("app_type", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("ack", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("rst", org.apache.hadoop.record.meta.TypeID.IntTypeID);

		_rio_recTypeInfo.addField("pure_ack", org.apache.hadoop.record.meta.TypeID.IntTypeID);		
		_rio_recTypeInfo.addField("unique_bytes", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("data_pkts", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("data_bytes", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("rexmit_pkts", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("rexmit_bytes", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("out_seq_pkts", org.apache.hadoop.record.meta.TypeID.IntTypeID);		
		_rio_recTypeInfo.addField("syn", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("fin", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("ws", org.apache.hadoop.record.meta.TypeID.BoolTypeID);
		_rio_recTypeInfo.addField("ts", org.apache.hadoop.record.meta.TypeID.BoolTypeID);
		_rio_recTypeInfo.addField("win_scale", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		
		_rio_recTypeInfo.addField("sack_req", org.apache.hadoop.record.meta.TypeID.BoolTypeID);//
		_rio_recTypeInfo.addField("sack_sent", org.apache.hadoop.record.meta.TypeID.IntTypeID); //
		_rio_recTypeInfo.addField("mss", org.apache.hadoop.record.meta.TypeID.IntTypeID); 
		_rio_recTypeInfo.addField("seq_max", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("seq_min", org.apache.hadoop.record.meta.TypeID.LongTypeID);			
		_rio_recTypeInfo.addField("win_max", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("win_min", org.apache.hadoop.record.meta.TypeID.IntTypeID);		
		_rio_recTypeInfo.addField("cnt_zerowin", org.apache.hadoop.record.meta.TypeID.IntTypeID);	
		_rio_recTypeInfo.addField("cwin_max", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("cwin_min", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("initial_cwin", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		
		_rio_recTypeInfo.addField("tot_rtt", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("rtt_min", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("rtt_max", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("ttl", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("ttl_max", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("ttl_min", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("timeout", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("dup3ack", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("reordering", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("net_dup", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("unknown", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("first_time", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("last_time", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("direction", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("acknum", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("tcp", org.apache.hadoop.record.meta.TypeID.BoolTypeID);
		_rio_recTypeInfo.addField("rtt_cnt", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("payload", org.apache.hadoop.record.meta.TypeID.BufferTypeID);
		_rio_recTypeInfo.addField("http_type", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("firstkey", org.apache.hadoop.record.meta.TypeID.BufferTypeID);
		_rio_recTypeInfo.addField("secondkey", org.apache.hadoop.record.meta.TypeID.BufferTypeID);
		_rio_recTypeInfo.addField("iscomplete", org.apache.hadoop.record.meta.TypeID.BoolTypeID);
	}

	protected static final long serialVersionUID = -8856988406589484129L;
	
//	private byte[] firstkey;
//	private byte[] secondkey;
	private byte[] reversekey;
	EZBytes eb;
//	private int classify_state;

	protected String src_ip;
	protected String  dst_ip;
	protected int src_port;
	protected int dst_port;
	protected long packets;
	protected int app_type;
	protected int ack;
	protected int rst;

	protected int pure_ack;
	public Buffer getSecondkey() {
		return secondkey;
	}

	public void setSecondkey(Buffer secondkey) {
		this.secondkey = secondkey;
	}

	protected long unique_bytes;
	protected long data_pkts;
	protected long data_bytes;
	protected int rexmit_pkts;
	protected int rexmit_bytes;
	protected int out_seq_pkts;
	protected int syn;
	protected int fin;
	protected boolean ws;
	protected boolean ts;
	protected int win_scale;
	
	protected boolean sack_req;
	protected int sack_sent;
	protected int mss;
	
	protected long seq_max;
	protected long seq_min;
	
	protected int win_max;
	protected int win_min;	
	protected int cnt_zerowin;
	
	protected int cwin_max;
	protected int cwin_min;
	protected int initial_cwin;
	
	protected long tot_rtt;
	protected long rtt_min;
	protected long rtt_max;
	
	protected int ttl;
	protected int ttl_max;
	protected int ttl_min;
	
	protected int timeout;
	protected int dup3ack;
	
	protected int reordering; //??
	protected int net_dup;
	protected int unknown;
	
	protected long first_time;
	protected long last_time;
	
	protected int direction;
	protected long acknum;
	protected boolean tcp;
	
	protected int rtt_cnt;
	protected Buffer payload;
	protected int http_type;
	
	protected Buffer firstkey;
	protected Buffer secondkey;	
	protected boolean iscomplete;	
	
	
	public Buffer getPayload() {
		return payload;
	}

	public void setPayload(byte[] payload) {
		this.payload.setCapacity(payload.length);
		this.payload.set(payload);
	}

	/** Packet data (excluding the header) */
//	protected byte[] data;

	public static org.apache.hadoop.record.meta.RecordTypeInfo getTypeInfo() {
		    return _rio_recTypeInfo;
	}

	public static void setTypeFilter(org.apache.hadoop.record.meta.RecordTypeInfo rti) {
	  if (null == rti) return;
	  _rio_rtiFilter = rti;
	  _rio_rtiFilterFields = null;
	}

	protected static void setupRtiFields()
	{
	  if (null == _rio_rtiFilter) return;
	  // we may already have done this
	  if (null != _rio_rtiFilterFields) return;
	  int _rio_i, _rio_j;
	  _rio_rtiFilterFields = new int [_rio_rtiFilter.getFieldTypeInfos().size()];
	  for (_rio_i=0; _rio_i<_rio_rtiFilterFields.length; _rio_i++) {
	    _rio_rtiFilterFields[_rio_i] = 0;
	  }
	  java.util.Iterator<org.apache.hadoop.record.meta.FieldTypeInfo> _rio_itFilter = _rio_rtiFilter.getFieldTypeInfos().iterator();
	  _rio_i=0;
	  while (_rio_itFilter.hasNext()) {
	    org.apache.hadoop.record.meta.FieldTypeInfo _rio_tInfoFilter = _rio_itFilter.next();
	    java.util.Iterator<org.apache.hadoop.record.meta.FieldTypeInfo> _rio_it = _rio_recTypeInfo.getFieldTypeInfos().iterator();
	    _rio_j=1;
	    while (_rio_it.hasNext()) {
	      org.apache.hadoop.record.meta.FieldTypeInfo _rio_tInfo = _rio_it.next();
	      if (_rio_tInfo.equals(_rio_tInfoFilter)) {
	        _rio_rtiFilterFields[_rio_i] = _rio_j;
	        break;
	      }
	      _rio_j++;
	    }
	    _rio_i++;
	  }
	}

	@Override
	public int compareTo(Object obj) throws ClassCastException {
		// TODO Auto-generated method stub
		PacketStatsWritable other = (PacketStatsWritable)obj;
		
		int cmp = this.getFirstkey().hashCode()>other.getFirstkey().hashCode()?1
				:this.getFirstkey().hashCode()==other.getFirstkey().hashCode()?0:-1;
		if (cmp != 0) {
			return cmp;
		}
		cmp = this.getFirst_time()>other.getFirst_time()?1:this.getFirst_time()==other.getFirst_time()?0:-1;
		if (cmp != 0) {
			return cmp;
		}
		return this.getDirection() == C2S? 1:-1;
	}

	protected void deserializeWithoutFilter(final org.apache.hadoop.record.RecordInput _rio_a, final String _rio_tag)
		throws java.io.IOException {
		
		// TODO Auto-generated method stub
	    _rio_a.startRecord(_rio_tag); 

	    this.src_ip = _rio_a.readString("src_ip");
	    this.dst_ip = _rio_a.readString("dst_ip");
	    this.src_port = _rio_a.readInt("src_port");
	    this.dst_port = _rio_a.readInt("dst_port");
	    this.packets = _rio_a.readLong("packets");
	    this.app_type = _rio_a.readInt("app_type");
	    this.ack = _rio_a.readInt("ack");
	    this.rst = _rio_a.readInt("rst");

	    this.pure_ack = _rio_a.readInt("pure_ack");
	    this.unique_bytes = _rio_a.readLong("unique_bytes");
	    this.data_pkts = _rio_a.readLong("data_pkts");
	    this.data_bytes = _rio_a.readLong("data_bytes");
	    this.rexmit_pkts = _rio_a.readInt("rexmit_pkts");
	    this.rexmit_bytes = _rio_a.readInt("rexmit_bytes");
	    this.out_seq_pkts = _rio_a.readInt("out_seq_pkts");
	    this.syn = _rio_a.readInt("syn");
	    this.fin = _rio_a.readInt("fin");
	    this.ws = _rio_a.readBool("ws");
	    this.ts = _rio_a.readBool("ts");
	    this.win_scale = _rio_a.readInt("win_scale");

	    this.sack_req = _rio_a.readBool("sack_req");
	    this.sack_sent = _rio_a.readInt("sack_sent");
	    this.mss = _rio_a.readInt("mss");
	    this.seq_max = _rio_a.readLong("seq_max");
	    this.seq_min = _rio_a.readLong("seq_min");
	    this.win_max = _rio_a.readInt("win_max");
	    this.win_min = _rio_a.readInt("win_min");
	    this.cnt_zerowin = _rio_a.readInt("cnt_zerowin");
	    this.cwin_max = _rio_a.readInt("cwin_max");
	    this.cwin_min = _rio_a.readInt("cwin_min");
	    this.initial_cwin = _rio_a.readInt("initial_cwin");

	    this.tot_rtt = _rio_a.readLong("tot_rtt");
	    this.rtt_min = _rio_a.readLong("rtt_min");
	    this.rtt_max = _rio_a.readLong("rtt_max");
	    this.ttl = _rio_a.readInt("ttl");
	    this.ttl_max = _rio_a.readInt("ttl_max");
	    this.ttl_min = _rio_a.readInt("ttl_min");
	    this.timeout = _rio_a.readInt("timeout");
	    this.dup3ack = _rio_a.readInt("dup3ack");
	    this.reordering = _rio_a.readInt("reordering");
	    this.net_dup = _rio_a.readInt("net_dup");
	    this.unknown = _rio_a.readInt("unknown");
	    this.first_time = _rio_a.readLong("first_time");
	    this.last_time = _rio_a.readLong("last_time");
	    this.direction = _rio_a.readInt("direction");
	    this.acknum = _rio_a.readLong("acknum");
	    this.tcp = _rio_a.readBool("tcp");
	    this.rtt_cnt = _rio_a.readInt("rtt_cnt");	    
	    this.payload = _rio_a.readBuffer("payload");
	    this.http_type = _rio_a.readInt("http_type");
	    this.firstkey = _rio_a.readBuffer("firstkey");
	    this.secondkey = _rio_a.readBuffer("secondkey");
	    this.iscomplete = _rio_a.readBool("iscomplete");
	    _rio_a.endRecord(_rio_tag);		
	}
	
	public void deserialize(final org.apache.hadoop.record.RecordInput _rio_a, final String _rio_tag)
	throws java.io.IOException {
	  if (null == _rio_rtiFilter) {
	    deserializeWithoutFilter(_rio_a, _rio_tag);
	    return;
	  }
	  // if we're here, we need to read based on version info
	  _rio_a.startRecord(_rio_tag);
	  setupRtiFields();
	  for (int _rio_i=0; _rio_i<_rio_rtiFilter.getFieldTypeInfos().size(); _rio_i++) {

		if (1 == _rio_rtiFilterFields[_rio_i]) { src_ip = _rio_a.readString("src_ip");}
		else if (2 == _rio_rtiFilterFields[_rio_i]) { dst_ip = _rio_a.readString("dst_ip");}
		else if (3 == _rio_rtiFilterFields[_rio_i]) { src_port = _rio_a.readInt("src_port");}
		else if (4 == _rio_rtiFilterFields[_rio_i]) { dst_port = _rio_a.readInt("dst_port");}
		else if (5 == _rio_rtiFilterFields[_rio_i]) { packets = _rio_a.readLong("packets");}
		else if (6 == _rio_rtiFilterFields[_rio_i]) { app_type = _rio_a.readInt("app_type");}
		else if (7 == _rio_rtiFilterFields[_rio_i]) { ack = _rio_a.readInt("ack");}
		else if (8 == _rio_rtiFilterFields[_rio_i]) { rst = _rio_a.readInt("rst");}
	
		else if (9 == _rio_rtiFilterFields[_rio_i]) { pure_ack = _rio_a.readInt("pure_ack");}
		else if (10 == _rio_rtiFilterFields[_rio_i]) { unique_bytes = _rio_a.readLong("unique_bytes");}
		else if (11 == _rio_rtiFilterFields[_rio_i]) { data_pkts = _rio_a.readLong("data_pkts");}
		else if (12 == _rio_rtiFilterFields[_rio_i]) { data_bytes = _rio_a.readLong("data_bytes");}
		else if (13 == _rio_rtiFilterFields[_rio_i]) { rexmit_pkts = _rio_a.readInt("rexmit_pkts");}
		else if (14== _rio_rtiFilterFields[_rio_i]) { rexmit_bytes = _rio_a.readInt("rexmit_bytes");}
		else if (15 == _rio_rtiFilterFields[_rio_i]) { out_seq_pkts = _rio_a.readInt("out_seq_pkts");}
		else if (16 == _rio_rtiFilterFields[_rio_i]) { syn = _rio_a.readInt("syn");}
		else if (17 == _rio_rtiFilterFields[_rio_i]) { fin = _rio_a.readInt("fin");}
		else if (18 == _rio_rtiFilterFields[_rio_i]) { ws = _rio_a.readBool("ws");}
		else if (19 == _rio_rtiFilterFields[_rio_i]) { ts = _rio_a.readBool("ts");}
		else if (20 == _rio_rtiFilterFields[_rio_i]) { win_scale = _rio_a.readInt("win_scale");}
		
		else if (21 == _rio_rtiFilterFields[_rio_i]) { sack_req = _rio_a.readBool("sack_req");}
		else if (22 == _rio_rtiFilterFields[_rio_i]) { sack_sent = _rio_a.readInt("sack_sent");}
		else if (23 == _rio_rtiFilterFields[_rio_i]) { mss = _rio_a.readInt("mss");}
		else if (24 == _rio_rtiFilterFields[_rio_i]) { seq_max = _rio_a.readLong("seq_max");}
		else if (25 == _rio_rtiFilterFields[_rio_i]) { seq_min = _rio_a.readLong("seq_min");}
		else if (26 == _rio_rtiFilterFields[_rio_i]) { win_max = _rio_a.readInt("win_max");}
		else if (27 == _rio_rtiFilterFields[_rio_i]) { win_min = _rio_a.readInt("win_min");}
		else if (28 == _rio_rtiFilterFields[_rio_i]) { cnt_zerowin = _rio_a.readInt("cnt_zerowin");}
		else if (29 == _rio_rtiFilterFields[_rio_i]) { cwin_max = _rio_a.readInt("cwin_max");}
		else if (30 == _rio_rtiFilterFields[_rio_i]) { cwin_min = _rio_a.readInt("cwin_min");}
		else if (31 == _rio_rtiFilterFields[_rio_i]) { initial_cwin = _rio_a.readInt("initial_cwin");}
		
		else if (32 == _rio_rtiFilterFields[_rio_i]) { tot_rtt = _rio_a.readLong("tot_rtt");}
		else if (33 == _rio_rtiFilterFields[_rio_i]) { rtt_min = _rio_a.readLong("rtt_min");}
		else if (34 == _rio_rtiFilterFields[_rio_i]) { rtt_max = _rio_a.readLong("rtt_max");}
		else if (35 == _rio_rtiFilterFields[_rio_i]) { ttl = _rio_a.readInt("ttl");}
		else if (36 == _rio_rtiFilterFields[_rio_i]) { ttl_max = _rio_a.readInt("ttl_max");}
		else if (37 == _rio_rtiFilterFields[_rio_i]) { ttl_min = _rio_a.readInt("ttl_min");}
		else if (38 == _rio_rtiFilterFields[_rio_i]) { timeout = _rio_a.readInt("timeout");}
		else if (39 == _rio_rtiFilterFields[_rio_i]) { dup3ack = _rio_a.readInt("dup3ack");}
		else if (40 == _rio_rtiFilterFields[_rio_i]) { reordering = _rio_a.readInt("reordering");}
		else if (41 == _rio_rtiFilterFields[_rio_i]) { net_dup = _rio_a.readInt("net_dup");}
		else if (42 == _rio_rtiFilterFields[_rio_i]) { unknown = _rio_a.readInt("unknown");}
		else if (43 == _rio_rtiFilterFields[_rio_i]) { first_time = _rio_a.readLong("first_time");}
		else if (44 == _rio_rtiFilterFields[_rio_i]) { last_time = _rio_a.readLong("last_time");}
		else if (45 == _rio_rtiFilterFields[_rio_i]) { direction = _rio_a.readInt("direction");}
		else if (46 == _rio_rtiFilterFields[_rio_i]) { acknum = _rio_a.readLong("acknum");}
		else if (47 == _rio_rtiFilterFields[_rio_i]) { tcp = _rio_a.readBool("tcp");}
		else if (48 == _rio_rtiFilterFields[_rio_i]) { rtt_cnt = _rio_a.readInt("rtt_cnt");}
		else if (49 == _rio_rtiFilterFields[_rio_i]) { payload = _rio_a.readBuffer("payload");}
		else if (50 == _rio_rtiFilterFields[_rio_i]) { http_type = _rio_a.readInt("http_type");}
		else if (51 == _rio_rtiFilterFields[_rio_i]) { firstkey = _rio_a.readBuffer("firstkey");}
		else if (52 == _rio_rtiFilterFields[_rio_i]) { secondkey = _rio_a.readBuffer("secondkey");}
		else if (53 == _rio_rtiFilterFields[_rio_i]) { iscomplete = _rio_a.readBool("iscomplete");}
		else {
	      java.util.ArrayList<org.apache.hadoop.record.meta.FieldTypeInfo> typeInfos = (java.util.ArrayList<org.apache.hadoop.record.meta.FieldTypeInfo>)(_rio_rtiFilter.getFieldTypeInfos());
	      org.apache.hadoop.record.meta.Utils.skip(_rio_a, typeInfos.get(_rio_i).getFieldID(), typeInfos.get(_rio_i).getTypeID());
	    }
	  }
	  _rio_a.endRecord(_rio_tag);
	}	
	
	@Override
	public void serialize(final org.apache.hadoop.record.RecordOutput _rio_a, final String _rio_tag) throws IOException {
		// TODO Auto-generated method stub

	    _rio_a.startRecord(this,_rio_tag);
	    
		_rio_a.writeString(src_ip, "src_ip");
		_rio_a.writeString(dst_ip, "dst_ip");
		_rio_a.writeInt(src_port, "src_port");
		_rio_a.writeInt(dst_port, "dst_port");
		_rio_a.writeLong(packets, "packets");
		_rio_a.writeInt(app_type, "app_type");
		_rio_a.writeInt(ack, "ack");
		_rio_a.writeInt(rst, "rst");

		_rio_a.writeInt(pure_ack, "pure_ack");
		_rio_a.writeLong(unique_bytes, "unique_bytes");
		_rio_a.writeLong(data_pkts, "data_pkts");
		_rio_a.writeLong(data_bytes, "data_bytes");
		_rio_a.writeInt(rexmit_pkts, "rexmit_pkts");
		_rio_a.writeInt(rexmit_bytes, "rexmit_bytes");
		_rio_a.writeInt(out_seq_pkts, "out_seq_pkts");
		_rio_a.writeInt(syn, "syn");
		_rio_a.writeInt(fin, "fin");
		_rio_a.writeBool(ws, "ws");
		_rio_a.writeBool(ts, "ts");
		_rio_a.writeInt(win_scale, "win_scale");
		
		_rio_a.writeBool(sack_req, "sack_req");
		_rio_a.writeInt(sack_sent, "sack_sent");
		_rio_a.writeInt(mss, "mss");
		_rio_a.writeLong(seq_max, "seq_max");
		_rio_a.writeLong(seq_min, "seq_min");
		_rio_a.writeInt(win_max, "win_max");
		_rio_a.writeInt(win_min, "win_min");
		_rio_a.writeInt(cnt_zerowin, "cnt_zerowin");
		_rio_a.writeInt(cwin_max, "cwin_max");
		_rio_a.writeInt(cwin_min, "cwin_min");
		_rio_a.writeInt(initial_cwin, "initial_cwin");
		
		_rio_a.writeLong(tot_rtt, "tot_rtt");
		_rio_a.writeLong(rtt_min, "rtt_min");
		_rio_a.writeLong(rtt_max, "rtt_max");
		_rio_a.writeInt(ttl, "ttl");
		_rio_a.writeInt(ttl_max, "ttl_max");
		_rio_a.writeInt(ttl_min, "ttl_min");
		_rio_a.writeInt(timeout, "timeout");
		_rio_a.writeInt(dup3ack, "dup3ack");
		_rio_a.writeInt(reordering, "reordering");
		_rio_a.writeInt(net_dup, "net_dup");
		_rio_a.writeInt(unknown, "unknown");
		_rio_a.writeLong(first_time, "first_time");
		_rio_a.writeLong(last_time, "last_time");	
		_rio_a.writeInt(direction, "direction");
		_rio_a.writeLong(acknum, "acknum");
		_rio_a.writeBool(tcp, "tcp");
		_rio_a.writeInt(rtt_cnt, "rtt_cnt");
		_rio_a.writeBuffer(payload, "payload");
		_rio_a.writeInt(http_type, "http_type");
		_rio_a.writeBuffer(firstkey, "firstkey");		
		_rio_a.writeBuffer(secondkey, "secondkey");	
		_rio_a.writeBool(iscomplete, "iscomplete");
		
	    _rio_a.endRecord(this,_rio_tag);
	}

	public PacketStatsWritable(){  	
		
		src_ip = "";
		dst_ip = "";
		src_port = -1;
		dst_port = -1;
		
	    packets = 0;
		packets = 0;
		app_type = 0;
		ack = 0;
		rst = 0;

		pure_ack = 0;
		unique_bytes = 0;
		data_pkts = 0;
		data_bytes = 0;
		rexmit_pkts = 0;
		rexmit_bytes = 0;
		out_seq_pkts = 0;
		syn = 0;
		fin = 0;
		ws = false;
		ts = false;
		win_scale = 0;
		
		sack_req = false;
		sack_sent = 0;
		mss = 0;
		
    	seq_max = Long.MIN_VALUE;
    	seq_min = Long.MAX_VALUE;	
    	
		win_max = Integer.MIN_VALUE;
		win_min = Integer.MAX_VALUE;
		cnt_zerowin = 0;
		
		cwin_max = Integer.MIN_VALUE;
		cwin_min = Integer.MAX_VALUE;
		initial_cwin = 0;
		
		tot_rtt = 0;
		rtt_max = Long.MIN_VALUE;
		rtt_min = Long.MAX_VALUE;
		
		ttl = -1;
		ttl_max = Integer.MIN_VALUE;
		ttl_min = Integer.MAX_VALUE;
		
		timeout = 0;
		dup3ack = 0;
		
		reordering = 0; //??
		net_dup = 0;
		unknown = 0;
		
		first_time = Long.MAX_VALUE;
		last_time = Long.MIN_VALUE;	
		
		direction = PacketStatsWritable.NONE;
		acknum = 0;
		tcp = false;		
		rtt_cnt = 0;
		payload = new Buffer();
		http_type=0;
		firstkey = new Buffer();
		secondkey = new Buffer();
		iscomplete = false;
	}
    	
	public PacketStatsWritable(String src_ip, String dst_ip, int src_port,
			int dst_port, long packets, int app_type, int ack, int rst, int pure_ack,
			long unique_bytes, long data_pkts, long data_bytes,
			int rexmit_pkts, int rexmit_bytes, int out_seq_pkts, int syn,
			int fin, boolean ws, boolean ts,int win_scale, boolean sack_req, int sack_sent,
			int mss, long seq_max, long seq_min, int win_max, int win_min,
			int cnt_zerowin, int cwin_max, int cwin_min, int initial_cwin, long tot_rtt,
			long rtt_min, long rtt_max, int ttl, int ttl_max, int ttl_min, int timeout, int dup3ack,
			int reordering, int net_dup, int unknown, long first_time,
			long last_time, int direction, long acknum, boolean tcp, int rtt_cnt, Buffer payload, int http_type, Buffer firstkey,Buffer secondkey, boolean iscomplete) {
		super();
		this.src_ip = src_ip;
		this.dst_ip = dst_ip;
		this.src_port = src_port;
		this.dst_port = dst_port;
		this.packets = packets;
		this.app_type = app_type;
		this.ack = ack;
		this.rst = rst;
		this.pure_ack = pure_ack;
		this.unique_bytes = unique_bytes;
		this.data_pkts = data_pkts;
		this.data_bytes = data_bytes;
		this.rexmit_pkts = rexmit_pkts;
		this.rexmit_bytes = rexmit_bytes;
		this.out_seq_pkts = out_seq_pkts;
		this.syn = syn;
		this.fin = fin;
		this.ws = ws;
		this.ts = ts;
		this.win_scale = win_scale;
		this.sack_req = sack_req;
		this.sack_sent = sack_sent;
		this.mss = mss;
		this.seq_max = seq_max;
		this.seq_min = seq_min;
		this.win_max = win_max;
		this.win_min = win_min;
		this.cnt_zerowin = cnt_zerowin;
		this.cwin_max = cwin_max;
		this.cwin_min = cwin_min;
		this.initial_cwin = initial_cwin;
		this.tot_rtt = tot_rtt;
		this.rtt_min = rtt_min;
		this.rtt_max = rtt_max;
		this.ttl = ttl;
		this.ttl_max = ttl_max;
		this.ttl_min = ttl_min;
		this.timeout = timeout;
		this.dup3ack = dup3ack;
		this.reordering = reordering;
		this.net_dup = net_dup;
		this.unknown = unknown;
		this.first_time = first_time;
		this.last_time = last_time;
		this.direction = direction;
		this.acknum = acknum;
		this.tcp = tcp;
		this.rtt_cnt = rtt_cnt;
		this.payload = payload;
		this.http_type = http_type;
		this.firstkey = firstkey;
		this.secondkey = secondkey;
		this.iscomplete = iscomplete;
	}
	
	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		return super.equals(obj);
	}
	

	/**
	 * 
	 * @author dnlab
	 *
	 */
/*
	public static class Comparator extends org.apache.hadoop.record.RecordComparator {
	    public Comparator() {
	      super(TrackStats.class);
	    }
	    static public int slurpRaw(byte[] b, int s, int l) {
	      try {
	        int os = s;
	        {
	          int i = org.apache.hadoop.record.Utils.readVInt(b, s);
	          int z = org.apache.hadoop.record.Utils.getVIntSize(i);
	          s+=z; l-=z;
	        }
	        {
	          int i = org.apache.hadoop.record.Utils.readVInt(b, s);
	          int z = org.apache.hadoop.record.Utils.getVIntSize(i);
	          s+=z; l-=z;
	        }
	        {
	          int i = org.apache.hadoop.record.Utils.readVInt(b, s);
	          int z = org.apache.hadoop.record.Utils.getVIntSize(i);
	          s+=z; l-=z;
	        }
	        {
	          int i = org.apache.hadoop.record.Utils.readVInt(b, s);
	          int z = org.apache.hadoop.record.Utils.getVIntSize(i);
	          s+=z; l-=z;
	        }
	        {
	          int i = org.apache.hadoop.record.Utils.readVInt(b, s);
	          int z = org.apache.hadoop.record.Utils.getVIntSize(i);
	          s+=z; l-=z;
	        }
	        return (os - s);
	      } catch(java.io.IOException e) {
	        throw new RuntimeException(e);
	      }
	    }
	    static public int compareRaw(byte[] b1, int s1, int l1,
	                                   byte[] b2, int s2, int l2) {
	      try {
	        int os1 = s1;
	        {
	          int i1 = org.apache.hadoop.record.Utils.readVInt(b1, s1);
	          int i2 = org.apache.hadoop.record.Utils.readVInt(b2, s2);
	          if (i1 != i2) {
	            return ((i1-i2) < 0) ? -1 : 0;
	          }
	          int z1 = org.apache.hadoop.record.Utils.getVIntSize(i1);
	          int z2 = org.apache.hadoop.record.Utils.getVIntSize(i2);
	          s1+=z1; s2+=z2; l1-=z1; l2-=z2;
	        }
	        {
	          int i1 = org.apache.hadoop.record.Utils.readVInt(b1, s1);
	          int i2 = org.apache.hadoop.record.Utils.readVInt(b2, s2);
	          if (i1 != i2) {
	            return ((i1-i2) < 0) ? -1 : 0;
	          }
	          int z1 = org.apache.hadoop.record.Utils.getVIntSize(i1);
	          int z2 = org.apache.hadoop.record.Utils.getVIntSize(i2);
	          s1+=z1; s2+=z2; l1-=z1; l2-=z2;
	        }
	        {
	          int i1 = org.apache.hadoop.record.Utils.readVInt(b1, s1);
	          int i2 = org.apache.hadoop.record.Utils.readVInt(b2, s2);
	          if (i1 != i2) {
	            return ((i1-i2) < 0) ? -1 : 0;
	          }
	          int z1 = org.apache.hadoop.record.Utils.getVIntSize(i1);
	          int z2 = org.apache.hadoop.record.Utils.getVIntSize(i2);
	          s1+=z1; s2+=z2; l1-=z1; l2-=z2;
	        }
	        {
	          int i1 = org.apache.hadoop.record.Utils.readVInt(b1, s1);
	          int i2 = org.apache.hadoop.record.Utils.readVInt(b2, s2);
	          if (i1 != i2) {
	            return ((i1-i2) < 0) ? -1 : 0;
	          }
	          int z1 = org.apache.hadoop.record.Utils.getVIntSize(i1);
	          int z2 = org.apache.hadoop.record.Utils.getVIntSize(i2);
	          s1+=z1; s2+=z2; l1-=z1; l2-=z2;
	        }
	        {
	          int i1 = org.apache.hadoop.record.Utils.readVInt(b1, s1);
	          int i2 = org.apache.hadoop.record.Utils.readVInt(b2, s2);
	          if (i1 != i2) {
	            return ((i1-i2) < 0) ? -1 : 0;
	          }
	          int z1 = org.apache.hadoop.record.Utils.getVIntSize(i1);
	          int z2 = org.apache.hadoop.record.Utils.getVIntSize(i2);
	          s1+=z1; s2+=z2; l1-=z1; l2-=z2;
	        }
	        return (os1 - s1);
	      } catch(java.io.IOException e) {
	        throw new RuntimeException(e);
	      }
	    }
	    public int compare(byte[] b1, int s1, int l1,
	                         byte[] b2, int s2, int l2) {
	      int ret = compareRaw(b1,s1,l1,b2,s2,l2);
	      return (ret == -1)? -1 : ((ret==0)? 1 : 0);}
	  }
	  
	  static {
	    org.apache.hadoop.record.RecordComparator.define(PacketStatsWritable.class, new Comparator());
	  }
*/
	public PacketStatsWritable clone(PacketStatsWritable ps){
		
		ps.src_ip = src_ip;
		ps.dst_ip = dst_ip;
		ps.src_port = src_port;
		ps.dst_port = dst_port;
		ps.packets = packets;
		ps.sack_sent = sack_sent;
		ps.ack = ack;
		ps.rst = rst;
		ps.pure_ack = pure_ack;
		ps.unique_bytes = unique_bytes;
		ps.data_pkts = data_pkts;
		ps.data_bytes = data_bytes;
		ps.rexmit_pkts = rexmit_pkts;
		ps.rexmit_bytes = rexmit_bytes;
		ps.out_seq_pkts = out_seq_pkts;
		ps.syn = syn;
		ps.fin = fin;
		ps.ws = ws;
		ps.ts = ts;
		ps.win_scale = win_scale;
		ps.sack_req = sack_req;
		ps.sack_sent = sack_sent;
		ps.mss = mss;
		ps.seq_max = seq_max;
		ps.seq_min = seq_min;
		ps.win_max = win_max;
		ps.win_min = win_min;
		ps.cnt_zerowin = cnt_zerowin;
		ps.cwin_max = cwin_max;
		ps.cwin_min = cwin_min;
		ps.initial_cwin = initial_cwin;
		ps.tot_rtt = tot_rtt;
		ps.rtt_min = rtt_min;
		ps.rtt_max = rtt_max;
		ps.ttl = ttl;
		ps.ttl_max = ttl_max;
		ps.ttl_min = ttl_min;
		ps.timeout = timeout;
		ps.dup3ack = dup3ack;
		ps.reordering = reordering;
		ps.net_dup = net_dup;
		ps.unknown = unknown;
		ps.first_time = first_time;
		ps.last_time = last_time;
		ps.direction = direction;
		ps.acknum = acknum;
		ps.tcp = tcp;
		ps.rtt_cnt = rtt_cnt;
		ps.payload = payload;
		ps.http_type = http_type;
		ps.firstkey = firstkey;
		ps.secondkey = secondkey;
		ps.iscomplete = iscomplete;
		
		return ps;
	}  

	public boolean parse(byte[] pdata){
		
		eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		
		byte[] first_key = new byte[13];
		byte[] second_key = new byte[8];
		byte[] reverse_key = new byte[13];
	
		//check ip_protocol
		if(eb.GetShort(NewPcapRec.POS_ETH_TYPE) != EthernetPacket.ETHERTYPE_IP) 
			return false;

		// ...| time_sec | time_usec
		System.arraycopy(BinaryUtils.flipBO(eb.GetBytes(0, 4),4), 0, second_key, 0, 4);
		System.arraycopy(BinaryUtils.flipBO(eb.GetBytes(4, 4),4), 0, second_key, 4, 4);
		
		int capLen = Bytes.toInt(BinaryUtils.flipBO(eb.GetBytes(8, 4),4));
		int wiredLen = Bytes.toInt(BinaryUtils.flipBO(eb.GetBytes(12, 4),4));
		
		if(capLen < PacketStatsWritable.MIN_PKT_SIZE) return false;	
		
		int ipHLEN = (eb.GetByte(NewPcapRec.POS_IPHDR+NewPcapRec.POS_IP_HLEN)&0x0f)*4;
		int tcpHPOS = NewPcapRec.POS_IPHDR + ipHLEN;
		int totLEN = Bytes.toInt(eb.GetBytes(NewPcapRec.POS_IPHDR+NewPcapRec.POS_IP_TLEN,2));
	
		// C2S key ==> protocol | srcIP | dstIP | sPort |dPort
		System.arraycopy(pdata, NewPcapRec.POS_IPHDR + NewPcapRec.POS_IP_PROTO, first_key, 0, 1);	
		System.arraycopy(pdata, NewPcapRec.POS_IPHDR + NewPcapRec.POS_IP_SIP, first_key, 1, 8);	
		System.arraycopy(eb.GetBytes(tcpHPOS+NewPcapRec.POS_TCP_SPORT,4),0, first_key,9,4);
		
		// S2C key ==> protocol | dstIP | srcIP | dPort |sPort
		System.arraycopy(pdata, NewPcapRec.POS_IPHDR + NewPcapRec.POS_IP_PROTO, reverse_key, 0, 1);	
		System.arraycopy(pdata, NewPcapRec.POS_IPHDR + NewPcapRec.POS_IP_DIP, reverse_key, 1, 4);
		System.arraycopy(pdata, NewPcapRec.POS_IPHDR + NewPcapRec.POS_IP_SIP, reverse_key, 5, 4);
		System.arraycopy(pdata, tcpHPOS + NewPcapRec.POS_TCP_DPORT, reverse_key, 9, 2);
		System.arraycopy(pdata, tcpHPOS + NewPcapRec.POS_TCP_SPORT, reverse_key, 11, 2);
		
		this.firstkey.set(first_key);
		this.secondkey.set(second_key);
		this.reversekey = reverse_key;

		try {
			this.src_ip = InetAddress.getByAddress(eb.GetBytes(NewPcapRec.POS_IPHDR+NewPcapRec.POS_IP_SIP, 4)).toString();
			this.dst_ip = InetAddress.getByAddress(eb.GetBytes(NewPcapRec.POS_IPHDR+NewPcapRec.POS_IP_DIP, 4)).toString();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// tcp statistics
		return true;	
	}
	
	public Buffer getFirstkey() {
		return firstkey;
	}

	public void setFirstkey(Buffer firstkey) {
		this.firstkey = firstkey;
	}

	public String getSrc_ip() {
		return src_ip;
	}

	public void setSrc_ip(String src_ip) {
		this.src_ip = src_ip;
	}

	public String getDst_ip() {
		return dst_ip;
	}

	public void setDst_ip(String dst_ip) {
		this.dst_ip = dst_ip;
	}

	public int getSrc_port() {
		return src_port;
	}

	public void setSrc_port(int src_port) {
		this.src_port = src_port;
	}

	public int getDst_port() {
		return dst_port;
	}

	public void setDst_port(int dst_port) {
		this.dst_port = dst_port;
	}

	public long getPackets() {
		return packets;
	}

	public void setPackets(long packets) {
		this.packets = packets;
	}

	public int getAck() {
		return ack;
	}

	public void setAck(int ack) {
		this.ack = ack;
	}

	public int getRst() {
		return rst;
	}

	public void setRst(int rst) {
		this.rst = rst;
	}

	public int getPure_ack() {
		return pure_ack;
	}

	public void setPure_ack(int pure_ack) {
		this.pure_ack = pure_ack;
	}

	public long getUnique_bytes() {
		return unique_bytes;
	}

	public void setUnique_bytes(long unique_bytes) {
		this.unique_bytes = unique_bytes;
	}

	public long getData_pkts() {
		return data_pkts;
	}

	public void setData_pkts(long data_pkts) {
		this.data_pkts = data_pkts;
	}

	public long getData_bytes() {
		return data_bytes;
	}

	public void setData_bytes(long data_bytes) {
		this.data_bytes = data_bytes;
	}

	public int getRexmit_pkts() {
		return rexmit_pkts;
	}

	public void setRexmit_pkts(int rexmit_pkts) {
		this.rexmit_pkts = rexmit_pkts;
	}

	public int getRexmit_bytes() {
		return rexmit_bytes;
	}

	public void setRexmit_bytes(int rexmit_bytes) {
		this.rexmit_bytes = rexmit_bytes;
	}

	public int getOut_seq_pkts() {
		return out_seq_pkts;
	}

	public void setOut_seq_pkts(int out_seq_pkts) {
		this.out_seq_pkts = out_seq_pkts;
	}

	public int getSyn() {
		return syn;
	}

	public void setSyn(int syn) {
		this.syn = syn;
	}

	public int getFin() {
		return fin;
	}

	public void setFin(int fin) {
		this.fin = fin;
	}

	public boolean isWs() {
		return ws;
	}

	public void setWs(boolean ws) {
		this.ws = ws;
	}

	public boolean isTs() {
		return ts;
	}

	public void setTs(boolean ts) {
		this.ts = ts;
	}

	public int getWin_scale() {
		return win_scale;
	}

	public void setWin_scale(int win_scale) {
		this.win_scale = win_scale;
	}

	public boolean isSack_req() {
		return sack_req;
	}

	public void setSack_req(boolean sack_req) {
		this.sack_req = sack_req;
	}

	public int getSack_sent() {
		return sack_sent;
	}

	public void setSack_sent(int sack_sent) {
		this.sack_sent = sack_sent;
	}

	public int getMss() {
		return mss;
	}

	public void setMss(int mss) {
		this.mss = mss;
	}

	public long getSeq_max() {
		return seq_max;
	}

	public void setSeq_max(long seq_max) {
		this.seq_max = seq_max;
	}

	public long getSeq_min() {
		return seq_min;
	}

	public void setSeq_min(long seq_min) {
		this.seq_min = seq_min;
	}

	public int getWin_max() {
		return win_max;
	}

	public void setWin_max(int win_max) {
		this.win_max = win_max;
	}

	public int getWin_min() {
		return win_min;
	}

	public void setWin_min(int win_min) {
		this.win_min = win_min;
	}

	public int getCnt_zerowin() {
		return cnt_zerowin;
	}

	public void setCnt_zerowin(int cnt_zerowin) {
		this.cnt_zerowin = cnt_zerowin;
	}

	public int getCwin_max() {
		return cwin_max;
	}

	public void setCwin_max(int cwin_max) {
		this.cwin_max = cwin_max;
	}

	public int getCwin_min() {
		return cwin_min;
	}

	public void setCwin_min(int cwin_min) {
		this.cwin_min = cwin_min;
	}

	public int getInitial_cwin() {
		return initial_cwin;
	}

	public void setInitial_cwin(int initial_cwin) {
		this.initial_cwin = initial_cwin;
	}

	public long getTot_rtt() {
		return tot_rtt;
	}

	public void setTot_rtt(long tot_rtt) {
		this.tot_rtt = tot_rtt;
	}

	public long getRtt_min() {
		return rtt_min;
	}

	public void setRtt_min(long rtt_min) {
		this.rtt_min = rtt_min;
	}

	public long getRtt_max() {
		return rtt_max;
	}

	public void setRtt_max(long rtt_max) {
		this.rtt_max = rtt_max;
	}

	public int getTtl() {
		return ttl;
	}

	public void setTtl(int ttl) {
		this.ttl = ttl;
	}

	public int getTtl_max() {
		return ttl_max;
	}

	public void setTtl_max(int ttl_max) {
		this.ttl_max = ttl_max;
	}

	public int getTtl_min() {
		return ttl_min;
	}

	public void setTtl_min(int ttl_min) {
		this.ttl_min = ttl_min;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public int getDup3ack() {
		return dup3ack;
	}

	public void setDup3ack(int dup3ack) {
		this.dup3ack = dup3ack;
	}

	public int getReordering() {
		return reordering;
	}

	public void setReordering(int reordering) {
		this.reordering = reordering;
	}

	public int getNet_dup() {
		return net_dup;
	}

	public void setNet_dup(int net_dup) {
		this.net_dup = net_dup;
	}

	public int getUnknown() {
		return unknown;
	}

	public void setUnknown(int unknown) {
		this.unknown = unknown;
	}

	public long getFirst_time() {
		return first_time;
	}

	public void setFirst_time(long first_time) {
		this.first_time = first_time;
	}

	public long getLast_time() {
		return last_time;
	}

	public void setLast_time(long last_time) {
		this.last_time = last_time;
	}

	public int getDirection() {
		return direction;
	}

	public void setDirection(int direction) {
		this.direction = direction;
	}
	
	public boolean isIscomplete() {
		return iscomplete;
	}

	public void setIscomplete(boolean iscomplete) {
		this.iscomplete = iscomplete;
	}

	public long getAcknum() {
		return acknum;
	}

	public void setAcknum(long acknum) {
		this.acknum = acknum;
	}

	public boolean isTcp() {
		return tcp;
	}

	public void setTcp(boolean tcp) {
		this.tcp = tcp;
	}

	public int getRtt_cnt() {
		return rtt_cnt;
	}

	public void setRtt_cnt(int rtt_cnt) {
		this.rtt_cnt = rtt_cnt;
	}

	public byte[] getReversekey() {
		return reversekey;
	}

	public void setReversekey(byte[] reversekey) {
		this.reversekey = reversekey;
	}

	public int getApp_type() {
		return app_type;
	}

	public void setApp_type(int app_type) {
		this.app_type = app_type;
	}

	public int getHttp_type() {
		return http_type;
	}

	public void setHttp_type(int http_type) {
		this.http_type = http_type;
	}
}