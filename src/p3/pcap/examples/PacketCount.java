package p3.pcap.examples;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.*;
        
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import p3.common.lib.BinaryUtils;
import p3.common.lib.Bytes;
import p3.hadoop.mapreduce.lib.input.PcapInputFormat;
import p3.tcphttp.analyzer.lib.PacketStatsWritable;
        
public class PacketCount {
	
	private static final int PCAP_FILE_HEADER_LENGTH = 24;  
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
          
 public static void main(String[] args) throws Exception {
	
	String srcFilename = new String();   		
	boolean fh_skip = true;
	long cap_start = Long.MAX_VALUE;
	long cap_end = Long.MIN_VALUE;
	char argtype = 0;
	
	PacketCount pc = new PacketCount();
	Configuration conf = new Configuration();
	conf.addResource("p3-default.xml");
		
	/* Argument Parsing */
	int i = 0;
	while(i<args.length){
		if(args[i].startsWith("-")){
			
			argtype = args[i].charAt(1);
			switch (argtype){    					
			case 'R': case 'r':
				srcFilename += args[i].substring(2);
			}
		}
		i++;
	}
	
	/* get capture time automatically */
	Path inputPath = new Path(srcFilename);
	Path outputPath = new Path(srcFilename+"_out");
	FileSystem fs = FileSystem.get(URI.create(srcFilename), conf);
	InputStream in = null;
    byte[] buffer = new byte[PCAP_FILE_HEADER_LENGTH];
	Calendar cal = Calendar.getInstance();
	long timestamp = 0;
	
	if(cap_start == Long.MAX_VALUE){
		FileStatus stat = fs.getFileStatus(inputPath);
		if(stat.isDir()){
			FileStatus[] stats = fs.listStatus(inputPath);
			for(FileStatus curfs : stats){
				if(!curfs.isDir()){
					System.out.println(curfs.getPath());
					in = fs.open(curfs.getPath());
					if(fh_skip)
						in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
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
			if(fh_skip)
				in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
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
	
	/* end of capture time */        
	Job job = new Job(conf, "packetcount");
	job.setJarByClass(PacketCount.class);
  
	job.setOutputKeyClass(Text.class);
	job.setOutputValueClass(IntWritable.class);
	    
	job.setMapperClass(Map.class);
	job.setReducerClass(Reduce.class);
	    
	job.setInputFormatClass(PcapInputFormat.class);
	job.setOutputFormatClass(TextOutputFormat.class);
	
	conf.setLong("pcap.file.captime.min", cap_start);
	conf.setLong("pcap.file.captime.max", cap_end);
    
	FileInputFormat.addInputPath(job, inputPath);
	FileOutputFormat.setOutputPath(job, outputPath);
	
	fs = FileSystem.get(conf);
    // delete any output that might exist from a previous run of this job
    if (fs.exists(FileOutputFormat.getOutputPath(job))) {
      fs.delete(FileOutputFormat.getOutputPath(job), true);
    }  
    
	conf.getLong("pcap.file.captime.min", cap_start);
	conf.getLong("pcap.file.captime.max", cap_end);
	System.out.println(cap_start);
	System.out.println(cap_end);
	
    job.waitForCompletion(true);
 }
        
}