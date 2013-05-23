package p3.runner;

import java.io.IOException;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.*;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;
        
public class TracertAdj {
        
	 public static class Map extends Mapper<LongWritable, Text, Text, Text> {
	        		
	    public void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {
	    	
	        String line = value.toString();
	        String[] arrStr = line.split("\\|");
	        
	        if(arrStr.length!=15) return;
	        if(arrStr[10]=="0.0.0.0" || arrStr[10]=="0") return;  // exclude NAT address
	        
	        context.write(new Text(arrStr[4]+" "+arrStr[12]), new Text(1+"|"+arrStr[14]));
	    }
	 }
	 
	 public static class Combiner extends Reducer<Text, Text,  Text, Text> {

	    public void reduce(Text key, Iterable<Text> values, Context context) 
	      throws IOException, InterruptedException {
	        
	    	float sum = 0;
	    	int cnt = 0;
	    	
	        for (Text val : values) {
		        String[] arrStr = val.toString().split("\\|");
	        	cnt+=Integer.parseInt(arrStr[0]);
	        	sum += Float.parseFloat(arrStr[1]);
	        }
	        sum = Math.round(sum);
	        context.write(key, new Text(cnt+"|"+sum));
	    }
	 }
		 
	 
	 public static class Reduce extends Reducer<Text, Text,  NullWritable, Text> {

	    public void reduce(Text key, Iterable<Text> values, Context context) 
	      throws IOException, InterruptedException {
	        
	    	float sum = 0;
	    	int cnt = 0;
	    	long avg = 0;
	    	
	        for (Text val : values) {
		        String[] arrStr = val.toString().split("\\|");
	        	cnt+=Integer.parseInt(arrStr[0]);
	        	sum += Float.parseFloat(arrStr[1]);
	        }
	        avg=Math.round(sum/cnt);
	        context.write(NullWritable.get(), new Text(key+" "+cnt+" "+avg));
	    }
	 }
	 
	 private static void deleteOutpath(Job job, Configuration conf) throws IOException{
		 
		 FileSystem fs = FileSystem.get(conf);			
		 // delete any output that might exist from a previous run of this job
		 if (fs.exists(FileOutputFormat.getOutputPath(job))) {
			 fs.delete(FileOutputFormat.getOutputPath(job), true);
		 }
	 }
	        
	 public static void main(String[] args) throws Exception {
		 
		/* job 1 */ 
		Configuration conf = new Configuration();      
	    Job job = new Job(conf, "AdjacencyList");
	    
	    job.setJarByClass(TracertAdj.class);
	        
		String srcFilename = new String();   		
		char argtype = 0;
		
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

	    job.setMapperClass(Map.class);	
	    job.setReducerClass(Combiner.class);	
	    job.setReducerClass(Reduce.class);	
	    
	    job.setMapOutputKeyClass(Text.class);
	    job.setMapOutputValueClass(Text.class);
	    
	    job.setOutputKeyClass(NullWritable.class);
	    job.setOutputValueClass(Text.class);
	    
	    job.setInputFormatClass(TextInputFormat.class);
	    job.setOutputFormatClass(TextOutputFormat.class);
	    
	    FileInputFormat.setInputPaths(job, inputPath);
	    FileOutputFormat.setOutputPath(job, outputPath);
	    
	    deleteOutpath(job, conf);
	    
	    job.waitForCompletion(true);	    
	 }
        
}
