package p3.pcap.examples;

import java.io.IOException;
import java.util.*;
        
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.SequenceFileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import p3.tcphttp.analyzer.lib.TextPair;
        
public class PopularityCountUp {
        
 public static class Map extends Mapper<TextPair, IntWritable, Text, IntWritable> {
	 
    private final static IntWritable one = new IntWritable(1);
        
    public void map(TextPair key, IntWritable value, Context context) throws IOException, InterruptedException {
    	
		context.write(key.getFirst(), one);								
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
    Configuration conf = new Configuration();
        
    Job job = new Job(conf, "PopularityCountUp");
    
    job.setMapOutputKeyClass(TextPair.class);
    job.setMapOutputValueClass(IntWritable.class);
    
    job.setOutputKeyClass(Text.class);
    job.setOutputValueClass(IntWritable.class);
        
    job.setMapperClass(Map.class);
    job.setReducerClass(Reduce.class);
        
    job.setInputFormatClass(SequenceFileInputFormat.class);
    job.setOutputFormatClass(TextOutputFormat.class);
        
    FileInputFormat.addInputPath(job, new Path(args[0]));
    FileOutputFormat.setOutputPath(job, new Path(args[1]));
        
    job.waitForCompletion(true);
 }
        
}