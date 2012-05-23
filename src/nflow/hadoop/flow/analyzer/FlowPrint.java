package nflow.hadoop.flow.analyzer;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Calendar;
import java.util.Iterator;

import nflow.hadoop.analyzer.lib.FlowWritable;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
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
import p3.hadoop.common.util.Bytes;
import p3.hadoop.common.util.EZBytes;
import p3.hadoop.mapred.PcapInputFormat;

/**
 * NetFlow Ver.5 Packet Analysis
 * @author yhlee
 *
 */
public class FlowPrint {
	
	private static final int ONEDAYINSEC = 432000;
	
	public static class Map extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, NullWritable, FlowWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<NullWritable, FlowWritable> output, Reporter reporter) throws IOException {		
			
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
					if(fw.parse(count, timestamp, fdata)){
						output.collect(NullWritable.get(), fw);					
					}else{
//						reporter.incrCounter(COUNTER_KEYS.INVALID_LINES, 1);	
					}
					pos += FlowWritable.FLOW_LEN;
				}			
			} catch (NumberFormatException e) {							  
			}	
		}
	}
	
    public static class Reduce extends MapReduceBase 
	implements Reducer<NullWritable, FlowWritable, NullWritable, FlowWritable> {
	    public void reduce(NullWritable key, Iterator<FlowWritable> value,
	                    OutputCollector<NullWritable, FlowWritable> output, Reporter reporter)
	                    throws IOException {
	
	    	FlowWritable fw;
			
	    	while(value.hasNext()){
	    		// check first time & last time
	    		fw = value.next();
	            output.collect(NullWritable.get(), fw);   
	       }                
	    }
	}
    	
	public static class Iden_Map extends MapReduceBase 
	implements Mapper<BytesWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(BytesWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
			
				output.collect(key, value);					
		}
	}

    public static class Iden_Reduce extends MapReduceBase 
    	implements Reducer<NullWritable, FlowWritable, NullWritable, FlowWritable> {
        public void reduce(NullWritable key, Iterator<FlowWritable> value,
                        OutputCollector<NullWritable, FlowWritable> output, Reporter reporter)
                        throws IOException {

        	FlowWritable fw;
			
        	while(value.hasNext()){  
        		fw = value.next();
                output.collect(NullWritable.get(), fw);   
           }                
        }
    }
   	
	private void setCaptime(JobConf jobconf, FileSystem fs, String in_path, long cap_start) throws IOException{
		
		if(cap_start==-1) cap_start = Long.MAX_VALUE;
		long cap_end = Long.MIN_VALUE;
		boolean fh_exist = true;

		/* get capture time automatically */
		Path inputPath = new Path(in_path);
//		FileSystem fs = FileSystem.get(URI.create(in_path), jobconf);
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
//				fs.close();
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
//				fs.close();
			}				
		}

		if(cap_end == Long.MIN_VALUE)
			cap_end = cap_start+ONEDAYINSEC;
		
		jobconf.setLong("pcap.file.captime.min", cap_start);
		jobconf.setLong("pcap.file.captime.max", cap_end);
	}
	
	public void startFlowPrint(Configuration conf, String inpath, String outpath, long cap_start){
		
		JobConf jobconf = new JobConf(conf, FlowPrint.class);
		System.out.println(inpath + " ->"+ outpath);
		System.out.println(cap_start + " ->"+ cap_start);		
		
        jobconf.setJobName("flow_monitor");
//	    Path Output = new Path(jobconf.getJobName()+"_out"+"/"+ds);	
        
        jobconf.setInputFormat(PcapInputFormat.class);      
        jobconf.setOutputFormat(TextOutputFormat.class); 
        
        jobconf.setOutputKeyClass(NullWritable.class);
        jobconf.setOutputValueClass(FlowWritable.class);                                      
        jobconf.setMapperClass(Map.class);
        jobconf.setReducerClass(Reduce.class);
        jobconf.setNumReduceTasks(10);
             
        try {
			FileSystem fs = FileSystem.get(jobconf);
//			fs.setOwner(new_inpath, "hadoop", "supergroup");
	        FileInputFormat.setInputPaths(jobconf, new Path(inpath));
	        FileOutputFormat.setOutputPath(jobconf, new Path(outpath));

        	// set start time and end time
			setCaptime(jobconf, fs, inpath, cap_start);
			
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
	
	public void startFlowPrint(Configuration conf, String inpath, long cap_start){

		
//		Calendar cal = Calendar.getInstance();  
//		cal.setTimeInMillis(System.currentTimeMillis());	
//		String ds = String.format("%1$tY-%1$tm-%1$td.%1$tH%1$tM", cal);
		
		int idx = inpath.lastIndexOf("/");	
		if(idx!=-1){
			String outpath = "flow_monitor_out"+"/"+inpath.substring(idx);	
		    startFlowPrint(conf, inpath, outpath, cap_start);
		}else {
			String outpath = "flow_monitor_out"+"/"+inpath;	
		    startFlowPrint(conf, inpath, outpath, cap_start);
		}
	}
	
	public void startFlowPrint(String inpath, String outpath){		
		startFlowPrint(new Configuration(), inpath, outpath, -1);
	}
	
	public void startFlowPrint(String inpath){		
		startFlowPrint(new Configuration(), inpath, -1);
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		FlowPrint fp = new FlowPrint();
		long cap_start = -1;
		
		String inpath = args[0];
		String outpath = null;	
		
		if(args.length == 2){
			outpath = args[1];
			fp.startFlowPrint(new Configuration(), inpath, outpath, cap_start);
		}else{
			fp.startFlowPrint(new Configuration(), inpath, cap_start);
		}	
	}
}
