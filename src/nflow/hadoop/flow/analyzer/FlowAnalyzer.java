package nflow.hadoop.flow.analyzer;



import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Iterator;
import java.util.StringTokenizer;

import nflow.hadoop.analyzer.lib.FlowWritable;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reducer;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.TextOutputFormat;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.BitAdder;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.common.util.EZBytes;
import p3.hadoop.io.ExtendedBytesWritable;
import p3.hadoop.mapred.BinaryInputFormat;
import p3.hadoop.mapred.BinaryOutputFormat;
import p3.hadoop.mapred.PcapInputFormat;

/**
 * NetFlow Ver.5 Packet Analysis
 * @author yhlee
 * created by yhlee in 2012-03-26
 */
public class FlowAnalyzer {
	
	private static final int ONEDAYINSEC = 432000;
	
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
	public static class TotalVolume_Mapper extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, Text, Text>{
		
//		byte[] cntval = {0x01};
		String delimiter="|";
		
//		@Override
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<Text, Text> output, Reporter reporter) throws IOException {		
					
			byte[] value_bytes = value.getBytes();
			if(value_bytes.length < FlowWritable.MIN_PKT_SIZE + FlowWritable.PCAP_HLEN) return;	

			
			EZBytes eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			
			// C2S key ==> protocol | srcIP | dstIP | sPort |dPort
			long sys_uptime = Bytes.toLong(eb.GetBytes(FlowWritable.PCAP_ETHER_IP_UDP_HLEN+4,4));
			long timestamp = Bytes.toLong(eb.GetBytes(FlowWritable.PCAP_ETHER_IP_UDP_HLEN+8,4))*1000000
				+ Bytes.toLong(BinaryUtils.flipBO(eb.GetBytes(FlowWritable.PCAP_ETHER_IP_UDP_HLEN+12, 4),4));
			int count = eb.GetShort(FlowWritable.PCAP_ETHER_IP_UDP_HLEN+2);
			
			FlowWritable fw;
			byte[] fdata = new byte[FlowWritable.FLOW_LEN];
			int cnt_flows = 0;
			int pos = FlowWritable.PCAP_ETHER_IP_UDP_HLEN+FlowWritable.CFLOW_HLEN;
			
			try{
				while(cnt_flows++ < count){	
					fw = new FlowWritable();
					fdata = eb.GetBytes(pos, FlowWritable.FLOW_LEN);
					
					if(fw.parse(sys_uptime, timestamp, fdata)){
						
						/* confirm inbound or outbound */
						if(getInOutBound(value_bytes[POS_SIP],value_bytes[POS_SIP+1]) == OUTBOUND)	{
							// "SIP_OUT","DIP_OUT","SP_OUT","DP_OUT","SN_OUT"							
							output.collect(new Text("SIP_OUT"+delimiter+fw.getSrcaddr()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));							
							output.collect(new Text("DIP_OUT"+delimiter+fw.getDstaddr()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
							output.collect(new Text("SP_OUT"+delimiter+fw.getSrcport()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
							output.collect(new Text("DP_OUT"+delimiter+fw.getDstport()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
							output.collect(new Text("SSN_OUT"+delimiter+fw.getSrc_subnet()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));							
							output.collect(new Text("DSN_OUT"+delimiter+fw.getDst_subnet()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
							output.collect(new Text("SAS_OUT"+delimiter+fw.getSrc_as()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
							output.collect(new Text("DAS_OUT"+delimiter+fw.getDst_as()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
						}else{
							// "SIP_IN","DIP_IN","SP_IN","DP_IN","SN_IN"							
							output.collect(new Text("SIP_IN"+delimiter+fw.getSrcaddr()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));							
							output.collect(new Text("DIP_IN"+delimiter+fw.getDstaddr()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
							output.collect(new Text("SP_IN"+delimiter+fw.getSrcport()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
							output.collect(new Text("DP_IN"+delimiter+fw.getDstport()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
							output.collect(new Text("SSN_IN"+delimiter+fw.getSrc_subnet()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));							
							output.collect(new Text("DSN_IN"+delimiter+fw.getDst_subnet()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
							output.collect(new Text("SAS_IN"+delimiter+fw.getSrc_as()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
							output.collect(new Text("DAS_IN"+delimiter+fw.getDst_as()+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));							
						}
						
					}else{
//						reporter.incrCounter(COUNTER_KEYS.INVALID_LINES, 1);	
					}	
					pos += FlowWritable.FLOW_LEN;
				}			
			} catch (NumberFormatException e) {							  
			}
		}
	}
	
    public static class TotalVolume_Reducer extends MapReduceBase 
    	implements Reducer<Text, Text, Text, Text> {
    	
		String delimiter="|";	
		
		@Override
        public void reduce(Text key, Iterator<Text> values, OutputCollector<Text, Text> output, Reporter reporter)
                        throws IOException {
        	
        	StringTokenizer st = null;//new StringTokenizer();
        	long cntBytes = 0;
        	long cntPkts = 0;
        	long cntFlows = 0;
        	
        	while(values.hasNext()){  		 				
				st = new StringTokenizer(values.next().toString(), delimiter);
				while (st.hasMoreTokens()) {
				    cntBytes += Long.parseLong(st.nextToken());
				    cntPkts += Long.parseLong(st.nextToken());
				    cntFlows += Long.parseLong(st.nextToken());
				}
           }
           output.collect(key, new Text(delimiter+cntBytes+delimiter+cntPkts+delimiter+cntFlows));                   
        }
    }
    
	private void setCaptime(JobConf jobconf, String in_path, long cap_start) throws IOException{
		
		if(cap_start==-1) cap_start = Long.MAX_VALUE;
		long cap_end = Long.MIN_VALUE;
		boolean fh_exist = true;

		/* get capture time automatically */
		Path inputPath = new Path(in_path);
		FileSystem fs = FileSystem.get(URI.create(in_path), jobconf);
		InputStream in = null;
	    byte[] buffer = new byte[FlowWritable.PCAP_FILE_HEADER_LENGTH];
		long timestamp = 0;
		
		if(cap_start == Long.MAX_VALUE){
			FileStatus stat = fs.getFileStatus(inputPath);
			if(stat.isDir()){
				FileStatus[] stats = fs.listStatus(inputPath);
				for(FileStatus curfs : stats){
					if(!curfs.isDir()){
						System.out.println(curfs.getPath());
						in = fs.open(curfs.getPath());
						if(fh_exist)
							in.read(buffer, 0, FlowWritable.PCAP_FILE_HEADER_LENGTH);
						in.read(buffer, 0, 4);
						timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
						if(timestamp < cap_start)
							cap_start = timestamp;
						if(timestamp > cap_end)
							cap_end = timestamp;
					}
				}
				in.close();
				fs.close();
				cap_end = cap_end + ONEDAYINSEC;
				
			}else{
				in = fs.open(inputPath);
				if(fh_exist)
					in.read(buffer, 0, FlowWritable.PCAP_FILE_HEADER_LENGTH);
				in.read(buffer, 0, 4);
				timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
				System.out.println(timestamp);
				cap_start = timestamp;
				
				if(cap_end == Long.MIN_VALUE){
					cap_end = cap_start+ONEDAYINSEC;
				}
				in.close();
				fs.close();
			}				
		}

		if(cap_end == Long.MIN_VALUE)
			cap_end = cap_start+ONEDAYINSEC;
		
		jobconf.setLong("pcap.file.captime.min", cap_start);
		jobconf.setLong("pcap.file.captime.max", cap_end);
	}
    
	public void startFlowAnalyzer(Configuration conf, String inpath, String outpath, long cap_start){
		
		JobConf jobconf = new JobConf(conf, FlowAnalyzer.class);
		System.out.println(inpath + " ->"+ inpath);
		System.out.println(cap_start + " ->"+ cap_start);		
		
        jobconf.setJobName("flow_totalvolume");
//	    Path Output = new Path(jobconf.getJobName()+"_out"+"/"+ds);	
        
        jobconf.setInputFormat(PcapInputFormat.class);      
        jobconf.setOutputFormat(TextOutputFormat.class); 
        
        jobconf.setOutputKeyClass(Text.class);
        jobconf.setOutputValueClass(Text.class);
        
        jobconf.setMapperClass(TotalVolume_Mapper.class);
        jobconf.setCombinerClass(TotalVolume_Reducer.class);
        jobconf.setReducerClass(TotalVolume_Reducer.class);
        
        jobconf.setNumReduceTasks(10);
     
        FileInputFormat.setInputPaths(jobconf, new Path(inpath));
        FileOutputFormat.setOutputPath(jobconf, new Path(outpath));

        // set start time and end time
        try {
			setCaptime(jobconf, inpath, cap_start);
			
			FileSystem fs = FileSystem.get(jobconf);
			// delete any output that might exist from a previous run of this job
	        if (fs.exists(FileOutputFormat.getOutputPath(jobconf))) {
	          fs.delete(FileOutputFormat.getOutputPath(jobconf), true);
	        }

			JobClient.runJob(jobconf);
			
	        /* delete _logs */
	        Path output_logs = new Path(outpath + "/_logs");	
	        fs.delete(output_logs, true);
	        
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  		
	}
	
	
	public void startFlowAnalyzer(Configuration conf, String inpath, long cap_start){

		
//		Calendar cal = Calendar.getInstance();  
//		cal.setTimeInMillis(System.currentTimeMillis());	
//		String ds = String.format("%1$tY-%1$tm-%1$td.%1$tH%1$tM", cal);
		int idx = inpath.lastIndexOf("/");	
		if(idx!=-1){
			String outpath = "flow_totalvolume_out"+"/"+inpath.substring(idx);	
	    	startFlowAnalyzer(conf, inpath, outpath, cap_start);
		}else {
			String outpath = "flow_totalvolume_out"+"/"+inpath;	
	    	startFlowAnalyzer(conf, inpath, outpath, cap_start);
		}
	}
	
	public void startFlowAnalyzer(String inpath, String outpath){		
		startFlowAnalyzer(new Configuration(), inpath, outpath, -1);
	}
	
	public void startFlowAnalyzer(String inpath){		
		startFlowAnalyzer(new Configuration(), inpath, -1);
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		FlowAnalyzer fa = new FlowAnalyzer();
		long cap_start = -1;
		
		String inpath = args[0];
		String outpath = null;	
		
		if(args.length == 2){
			outpath = args[1];
			fa.startFlowAnalyzer(new Configuration(), inpath, outpath, cap_start);
		}else{
			fa.startFlowAnalyzer(new Configuration(), inpath, cap_start);
		}	
	}
}
