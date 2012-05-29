package p3.pcap.examples;

import java.io.IOException;
import java.util.*;
        
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.SequenceFileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import p3.hadoop.mapreduce.lib.input.PcapInputFormat;
import p3.tcphttp.analyzer.lib.PacketStatsWritable;
import p3.tcphttp.analyzer.lib.TextPair;
        
public class PopularityGen {
        
 public static class Map extends Mapper<LongWritable, BytesWritable, TextPair, IntWritable> {
	 
	private final int MIN_PKT_SIZE = 42;
    private final static IntWritable one = new IntWritable(1);
        
    public void map(LongWritable key, BytesWritable value, Context context) throws IOException, InterruptedException {
    	
		if(value.getBytes().length<MIN_PKT_SIZE) return;
		
		PacketStatsWritable ps = new PacketStatsWritable();
		
		if(ps.parse(value.getBytes()))		
			context.write(new TextPair(ps.getDst_ip(), ps.getSrc_ip()), one);								
	}
 } 
        
 public static class Reduce extends Reducer<TextPair, IntWritable, TextPair, IntWritable> {
	 
    private final static IntWritable one = new IntWritable(1);

    public void reduce(TextPair key, Iterable<IntWritable> values, Context context) 
      throws IOException, InterruptedException {
    	
        context.write(key, one);
    }
 }
        
 public static void main(String[] args) throws Exception {
    Configuration conf = new Configuration();
        
    Job job = new Job(conf, "popularityGen");
    
    job.setOutputKeyClass(TextPair.class);
    job.setOutputValueClass(IntWritable.class);
        
    job.setMapperClass(Map.class);
    job.setReducerClass(Reduce.class);
        
    job.setInputFormatClass(PcapInputFormat.class);
    job.setOutputFormatClass(SequenceFileOutputFormat.class);
        
    FileInputFormat.addInputPath(job, new Path(args[0]));
    FileOutputFormat.setOutputPath(job, new Path(args[1]));
        
    job.waitForCompletion(true);
 }
        
}