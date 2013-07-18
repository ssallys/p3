package nflow.hadoop.flow.analyzer;



import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Calendar;
import java.util.StringTokenizer;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import p3.common.lib.BinaryUtils;
import p3.common.lib.Bytes;
import p3.common.lib.EZBytes;
import p3.hadoop.mapreduce.lib.input.PcapInputFormat;
//import p3.hadoop.mapreduce.lib.input.PcapRealtimeFormat;


/**
 * NetFlow Ver.5 Packet Analysis
 * @author yhlee
 * created by yhlee in 2012-03-26
 */
public class FlowStats {
	
	private static final int ONEDAYINSEC = 432000;
		
	/**
	 * isStartwith 168.188 ?
	 * @param prefix1
	 * @param prefix2
	 * @return
	 */

	/*** OUTBOUND ***/
	public static class FlowStats_Mapper extends Mapper<LongWritable, BytesWritable, Text, Text>{
		
		String delimiter="|";
		long interval = 60*60 ;
		
		Calendar cal;
		
	    public void map(LongWritable key, BytesWritable value, Context context) throws IOException, InterruptedException {		
					
			byte[] value_bytes = value.getBytes();
			if(value_bytes.length < FlowWritable.MIN_PKT_SIZE + FlowWritable.PCAP_HLEN) return;	

			
			EZBytes eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			
			// C2S key ==> protocol | srcIP | dstIP | sPort |dPort
			long sys_uptime = Bytes.toLong(eb.GetBytes(FlowWritable.PCAP_ETHER_IP_UDP_HLEN+4,4));
			long timestamp = Bytes.toLong(eb.GetBytes(FlowWritable.PCAP_ETHER_IP_UDP_HLEN+8,4))*1000000
				+ Bytes.toLong(BinaryUtils.flipBO(eb.GetBytes(FlowWritable.PCAP_ETHER_IP_UDP_HLEN+12, 4),4));
			
//			Calendar cal = Calendar.getInstance();  
//			cal.setTimeInMillis((timestamp-(timestamp%(interval*1000000)))/1000);	
//			String maskedtime = String.format("%1$tY-%1$tm-%1$td %1$tH%1$tM", cal);
//			String maskedtime = ds.substring(0,13);
			
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
						context.write(new Text("srcPort"+delimiter+fw.getSrcport()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
						context.write(new Text("dstPort"+delimiter+fw.getDstport()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
						context.write(new Text("srcSubnet"+delimiter+fw.getSrc_subnet()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));							
						context.write(new Text("dstSubnet"+delimiter+fw.getDst_subnet()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
						context.write(new Text("srcAs"+delimiter+fw.getSrc_as()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));
						context.write(new Text("dstAs"+delimiter+fw.getDst_as()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));			
						context.write(new Text("totalProtocol"+delimiter+fw.getProt()), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
						context.write(new Text("totalVolume"+delimiter+"all"), new Text(fw.getdOctets()+delimiter+fw.getdPkts()+delimiter+"1"));	
						
					}else{
//						reporter.incrCounter(COUNTER_KEYS.INVALID_LINES, 1);	
					}	
					pos += FlowWritable.FLOW_LEN;
				}			
			} catch (NumberFormatException e) {							  
			}
		}
	}
	
    public static class FlowStats_Combiner extends Reducer<Text, Text, Text, Text> {
	
	String delimiter="|";	
	
		 public void reduce(Text key, Iterable<Text> values, Context context) throws IOException, InterruptedException {
	    	
	    	StringTokenizer st = null;
	    	long cntBytes = 0;
	    	long cntPkts = 0;
	    	long cntFlows = 0;
	    	
			 for (Text val : values) { 		 				
				st = new StringTokenizer(val.toString(), delimiter);
				while (st.hasMoreTokens()) {
				    cntBytes += Long.parseLong(st.nextToken());
				    cntPkts += Long.parseLong(st.nextToken());
				    cntFlows += Long.parseLong(st.nextToken());
				}
			 }
		       context.write(key, new Text(delimiter+cntBytes+delimiter+cntPkts+delimiter+cntFlows));                   
		 }
	}
    
    public static class FlowStats_Reducer extends Reducer<Text, Text, NullWritable, Text> {
    	
		String delimiter="|";	
		
		public void reduce(Text key, Iterable<Text> values, Context context) throws IOException, InterruptedException {
        	
        	StringTokenizer st = null;//new StringTokenizer();
        	long cntBytes = 0;
        	long cntPkts = 0;
        	long cntFlows = 0;
        	
        	for (Text val : values) { 	 		 				
				st = new StringTokenizer(val.toString(), delimiter);
				while (st.hasMoreTokens()) {
				    cntBytes += Long.parseLong(st.nextToken());
				    cntPkts += Long.parseLong(st.nextToken());
				    cntFlows += Long.parseLong(st.nextToken());
				}
           }
           context.write(NullWritable.get(), new Text(key.toString()+delimiter+cntBytes+delimiter+cntPkts+delimiter+cntFlows));                   
        }
    }
    
	private void setCaptime(Configuration conf, String in_path, long cap_start) throws IOException{
		
		if(cap_start==-1) cap_start = Long.MAX_VALUE;
		long cap_end = Long.MIN_VALUE;
		boolean fh_exist = true;

		/* get capture time automatically */
		Path inputPath = new Path(in_path);
		FileSystem fs = FileSystem.get(URI.create(in_path), conf);
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
		
		conf.setLong("pcap.file.captime.min", cap_start);
		conf.setLong("pcap.file.captime.max", cap_end);
	}
    
	public void startStats(Job job, String inpath, String outpath, long cap_start, int reducers, boolean isreal) throws IOException{
		
		System.out.println("flow Analyzer called!");		
		
        job.setJobName("flowStats"+inpath);
		job.setJarByClass(FlowStats.class); 
        
		if(isreal)
//			job.setInputFormatClass(PcapRealtimeFormat.class);    
			;
		else
			job.setInputFormatClass(PcapInputFormat.class);    
        job.setOutputFormatClass(TextOutputFormat.class); 
        
        job.setMapOutputKeyClass(Text.class);
        job.setMapOutputValueClass(Text.class);
        
        job.setOutputKeyClass(NullWritable.class);
        job.setOutputValueClass(Text.class);	
                
        job.setMapperClass(FlowStats_Mapper.class);
        job.setCombinerClass(FlowStats_Combiner.class);
        job.setReducerClass(FlowStats_Reducer.class);
        
        job.setNumReduceTasks(reducers);
     
        FileInputFormat.setInputPaths(job, new Path(inpath));
        FileOutputFormat.setOutputPath(job, new Path(outpath));

        // set start time and end time
        try {
			setCaptime(job.getConfiguration(), inpath, cap_start);
			
			FileSystem fs = FileSystem.get(job.getConfiguration());
			// delete any output that might exist from a previous run of this job
	        if (fs.exists(FileOutputFormat.getOutputPath(job))) {
	          fs.delete(FileOutputFormat.getOutputPath(job), true);
	        }

			job.waitForCompletion(true);
			
	        /* delete _logs */
	        Path output_logs = new Path(outpath + "/_logs");	
	        fs.delete(output_logs, true);
	        
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  		
	}
	
	
	public void startStats(Configuration conf, String inpath, long cap_start, int reducers, boolean isreal) throws IOException{

		
//		Calendar cal = Calendar.getInstance();  
//		cal.setTimeInMillis(System.currentTimeMillis());	
//		String ds = String.format("%1$tY-%1$tm-%1$td.%1$tH%1$tM", cal);
		Job job = new Job(conf);
		
		int idx = inpath.lastIndexOf("/");	
		if(idx!=-1){
			String outpath = "flowStats_out"+"/"+inpath.substring(idx+1);	
	    	startStats(job, inpath, outpath, cap_start, reducers, isreal);
		}else {
			String outpath = "flowStats_out"+"/"+inpath;	
	    	startStats(job, inpath, outpath, cap_start, reducers, isreal);
		}
	}
	
	public void startStats(String inpath, String outpath, int reducers) throws IOException{
		Configuration conf = new Configuration();
		Job job = new Job(conf);
		startStats(job, inpath, outpath, -1, reducers, false);
	}
	
	public void startStats(String inpath, int reducers, boolean isreal) throws IOException{		
		startStats(new Configuration(), inpath, -1, reducers, isreal);
	}
	
	public void startStats(String inpath, int reducers) throws IOException{		
		startStats(new Configuration(), inpath, -1, reducers, false);
	}
	
	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		FlowStats fa = new FlowStats();
		long cap_start = -1;
		
		String inpath = args[0];
		String outpath = null;	
		int reducers = Integer.parseInt(args[2]);
		
		if(args.length == 3){
			outpath = args[1];
			fa.startStats(inpath, outpath, reducers);
		}else{
			fa.startStats(new Configuration(), inpath, cap_start, reducers, false);
		}	
	}
}
