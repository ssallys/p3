package nflow.hadoop.flow.analyzer;



import java.io.IOException;
import java.util.Iterator;

import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reducer;
import org.apache.hadoop.mapred.Reporter;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.BitAdder;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.common.util.EZBytes;
import p3.hadoop.io.ExtendedBytesWritable;

/**
 * NetFlow Ver.5 Packet Analysis
 * @author yhlee
 * created by yhlee in 2012-03-26
 */
public class NetFlowAnalyzerwithNoTimerTask implements Runnable {
	
	String groupName[] = {"SIP_IN","DIP_IN","SP_IN","DP_IN","SN_IN","SIP_OUT","DIP_OUT","SP_OUT","DP_OUT","SN_OUT"};
	Class mapper[] = {SIP_Map_In.class, DIP_Map_In.class, SP_Map_In.class, DP_Map_In.class,
				Subnet_Map_In.class, SIP_Map_Out.class, DIP_Map_Out.class, SP_Map_Out.class,
		 		DP_Map_Out.class, Subnet_Map_Out.class};

	private static final int POS_SIP = 0;
	private static final int POS_DIP = 4;
	private static final int POS_SN = 0;
	private static final int POS_PT = 38;
	private static final int POS_SP = 32;
	private static final int POS_DP = 34;
	private static final int POS_BC = 20;
	private static final int POS_PC = 16;
	
	private static final int INBOUND = 1;
	private static final int OUTBOUND = 2;	
	
	JobConf conf;

	public NetFlowAnalyzerwithNoTimerTask(JobConf conf){
		this.conf = conf;
	}
	
	/**
	 * isStartwith 168.188 ?
	 * @param prefix1
	 * @param prefix2
	 * @return
	 */
	public static int getInOutBound(byte prefix1, byte prefix2){
		if((prefix1 & 0xa8)== 0xa8  && (prefix2 & 0xbc) ==  0xbc) return OUTBOUND;
		else return INBOUND;
	}
		
	/*** OUTBOUND ***/
	public static class SIP_Map_Out extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		
		byte[] cntval = {0x01};
		
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {				
			
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1]) == OUTBOUND)	{

				ExtendedBytesWritable SIP = new ExtendedBytesWritable(new byte[5]);
				SIP.set(value_bytes, POS_SIP, 0, 4);		
				SIP.set(value_bytes, POS_PT, 4, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(SIP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
	
 	//Port
	public static class DIP_Map_Out extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
					
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])== OUTBOUND){

				ExtendedBytesWritable DIP = new ExtendedBytesWritable(new byte[5]);
				DIP.set(value_bytes, POS_DIP, 0, 4);		
				DIP.set(value_bytes, POS_PT, 4, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(DIP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
 	//Port
	public static class SP_Map_Out extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {				
			
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])== OUTBOUND)	{
			
				ExtendedBytesWritable DP = new ExtendedBytesWritable(new byte[3]);
				DP.set(value_bytes, POS_SP, 0, 2);		
				DP.set(value_bytes, POS_PT, 2, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(DP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
	
 	//Port
	public static class DP_Map_Out extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
			
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])== OUTBOUND){
			
				ExtendedBytesWritable DP = new ExtendedBytesWritable(new byte[3]);
				DP.set(value_bytes, POS_DP, 0, 2);		
				DP.set(value_bytes, POS_PT, 2, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(DP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
	
 	//Port
	public static class Subnet_Map_Out extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
			
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])== OUTBOUND){
			
				ExtendedBytesWritable Subnet = new ExtendedBytesWritable(new byte[4]);
				Subnet.set(value_bytes, POS_SIP, 0, 3);		
				Subnet.set(value_bytes, POS_PT, 3, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(Subnet.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}	

	/*** INBOUND ***/
	public static class SIP_Map_In extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
			
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])== INBOUND){
	
				ExtendedBytesWritable SIP = new ExtendedBytesWritable(new byte[5]);
				SIP.set(value_bytes, POS_SIP, 0, 4);		
				SIP.set(value_bytes, POS_PT, 4, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(SIP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
	
 	//Port
	public static class DIP_Map_In extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
					
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])== INBOUND){

				ExtendedBytesWritable DIP = new ExtendedBytesWritable(new byte[5]);
				DIP.set(value_bytes, POS_DIP, 0, 4);		
				DIP.set(value_bytes, POS_PT, 4, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(DIP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
 	//Port
	public static class SP_Map_In extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {				
			
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1]) == INBOUND){
			
				ExtendedBytesWritable DP = new ExtendedBytesWritable(new byte[3]);
				DP.set(value_bytes, POS_SP, 0, 2);		
				DP.set(value_bytes, POS_PT, 2, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(DP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
	
 	//Port
	public static class DP_Map_In extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
			
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])==INBOUND){
				
				ExtendedBytesWritable DP = new ExtendedBytesWritable(new byte[3]);
				DP.set(value_bytes, POS_DP, 0, 2);		
				DP.set(value_bytes, POS_PT, 2, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(DP.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}
	
 	//Port
	public static class Subnet_Map_In extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
			
			byte[] cntval = {0x01};
			byte[] value_bytes = value.getBytes();

			/* confirm inbound or outbound */
			if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1])==INBOUND)	{
				
				ExtendedBytesWritable Subnet = new ExtendedBytesWritable(new byte[4]);
				Subnet.set(value_bytes, POS_SN, 0, 3);		
				Subnet.set(value_bytes, POS_PT, 3, 1);	
				
				ExtendedBytesWritable bpf = new ExtendedBytesWritable(new byte[24]);	
				bpf.set(value_bytes, POS_BC, 4, 4);				
				bpf.set(value_bytes, POS_PC, 12, 4);	
				bpf.set(cntval, 0, 23, 1);	
				
				output.collect(new BytesWritable(Subnet.getBytes()), new BytesWritable(bpf.getBytes()));
			}
		}
	}	
	
    public static class Reduce3 extends MapReduceBase 
    	implements Reducer<BytesWritable, BytesWritable, BytesWritable, BytesWritable> {
        public void reduce(BytesWritable key, Iterator<BytesWritable> value,
                        OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter)
                        throws IOException {
 
           byte[] sum = new byte[24];
 		   byte[] data = new byte[24];        	

           while(value.hasNext()){  
        	   data = value.next().getBytes();			 				
        	   sum = BitAdder.addBinary(sum, data, 24);
           }
           output.collect(key, new BytesWritable(sum));                   
        }
    }
    
	//thread Runnable Function
	public void run(){
		try{
		JobClient.runJob(conf);
		}
		catch (IOException e){}		
	}
}
