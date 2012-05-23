package p3.examples;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

import nflow.hadoop.analyzer.lib.FlowWritable;

import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.mapreduce.lib.input.PcapInputFormat;
import p3.jpcap.packet.PacketStatsWritable;
        
public class PacketCount {
	
	private static final int ONEDAYINSEC = 432000;
        
	 public static class Map extends Mapper<LongWritable, BytesWritable, Text, IntWritable> {
		 
	private final int MIN_PKT_SIZE = 42;
    private final static IntWritable one = new IntWritable(1);
        
    public void map(LongWritable key, BytesWritable value, Context context) throws IOException, InterruptedException {
    	
		if(value.getBytes().length<MIN_PKT_SIZE) return;
		
		PacketStatsWritable ps = new PacketStatsWritable();
		
		if(ps.parse(value.getBytes()))		
			context.write(new Text(ps.getSrc_ip()), one);								
	}
	 } 
	        
	 public static class Reduce extends Reducer<Text, IntWritable, Text, IntWritable> {
	
	    public void reduce(Text key, Iterable<IntWritable> values, Context context) 
	      throws IOException, InterruptedException {
	        int sum = 0;
	        for (IntWritable val : values) {
	            sum += val.get();
	        }
	        context.write(key, new IntWritable(sum));
	    }
	 }
 	
	private static void setCaptime(Configuration conf, FileSystem fs, String in_path, long cap_start) throws IOException{
		
		if(cap_start==-1) cap_start = Long.MAX_VALUE;
		long cap_end = Long.MIN_VALUE;
		boolean fh_exist = true;

		/* get capture time automatically */
		Path inputPath = new Path(in_path);
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
			}				
		}

		if(cap_end == Long.MIN_VALUE)
			cap_end = cap_start+ONEDAYINSEC;
		
		conf.setLong("pcap.file.captime.min", cap_start);
		conf.setLong("pcap.file.captime.max", cap_end);
	}
	
          
 public static void main(String[] args) throws Exception {
	
	String inpath = new String();   		
	long cap_start = Long.MAX_VALUE;
	long cap_end = Long.MIN_VALUE;
	char argtype = 0;
	
	Configuration conf = new Configuration();
	conf.addResource("p3-default.xml");
		
	/* Argument Parsing */
	int i = 0;
	while(i<args.length){
		if(args[i].startsWith("-")){
			
			argtype = args[i].charAt(1);
			switch (argtype){    					
			case 'R': case 'r':
				inpath += args[i].substring(2);
			}
		}
		i++;
	}
	
	/* get capture time automatically */
	Path inputPath = new Path(inpath);
	Path outputPath = new Path(inpath+"_out");
	FileSystem fs = FileSystem.get(URI.create(inpath), conf);

	if(cap_end == Long.MIN_VALUE)
		cap_end = cap_start+ONEDAYINSEC;
	
	/* end of capture time */        
	Job job = new Job(conf, "packetcount");
	job.setJarByClass(PacketCount.class);
  
	job.setOutputKeyClass(Text.class);
	job.setOutputValueClass(IntWritable.class);
	    
	job.setMapperClass(Map.class);
	job.setReducerClass(Reduce.class);
	    
	job.setInputFormatClass(PcapInputFormat.class);
	job.setOutputFormatClass(TextOutputFormat.class);
	   	
	fs = FileSystem.get(conf);
	FileInputFormat.addInputPath(job, inputPath);
	FileOutputFormat.setOutputPath(job, outputPath);

	// set start time and end time
	setCaptime(conf, fs, inpath, cap_start);
    // delete any output that might exist from a previous run of this job
    if (fs.exists(FileOutputFormat.getOutputPath(job))) {
      fs.delete(FileOutputFormat.getOutputPath(job), true);
    }   	        
    job.waitForCompletion(true);
 }
        
}