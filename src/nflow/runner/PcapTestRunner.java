package nflow.runner;


import java.io.IOException;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reducer;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.TextInputFormat;
import org.apache.hadoop.mapred.TextOutputFormat;
import org.apache.hadoop.mapred.lib.HashPartitioner;
import org.apache.hadoop.mapred.lib.IdentityMapper;
import org.apache.hadoop.mapred.lib.IdentityReducer;
import org.apache.hadoop.util.GenericOptionsParser;
import org.apache.hadoop.util.ToolRunner;

import p3.hadoop.mapred.PcapInputFormat;


public class PcapTestRunner {
	
	public static class PcapMapper extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, LongWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<LongWritable, BytesWritable> output, Reporter reporter) throws IOException {				
			output.collect(key,value);
		}
	}
    
	public static void main(String[] args) throws Exception {
		
		JobConf conf = new JobConf(PcapTestRunner.class);	

        conf.setJobName("pcapTest");    
        conf.setInputFormat(PcapInputFormat.class);
        conf.setOutputFormat(TextOutputFormat.class);        
        
        conf.setOutputKeyClass(LongWritable.class);
        conf.setOutputValueClass(BytesWritable.class);
        
        conf.setMapperClass(IdentityMapper.class);
        conf.setCombinerClass(IdentityReducer.class);
        conf.setReducerClass(IdentityReducer.class);	
        
        FileInputFormat.setInputPaths(conf, new Path("test1.pcap"));
        FileOutputFormat.setOutputPath(conf, new Path("test1"));
        
		JobClient.runJob(conf);
		
		
	}
}