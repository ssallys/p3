package nflow.hadoop.flow.analyzer;



import java.io.IOException;
import java.util.Iterator;

import nflow.runner.TestBinaryFlow;

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

import p3.hadoop.common.util.BitAdder;
import p3.hadoop.mapred.BinaryInputFormat;
import p3.hadoop.mapred.BinaryOutputFormat;

public class TestOneMonthBinaryFlow {
	  private static final int DEFAULT_RECORD_SIZE = 34;
		
		//Port
		public static class BytePerDPort_Map extends MapReduceBase 
		implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
			public void map
					(LongWritable key, BytesWritable value, 
					OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {
				
				BytesWritable Dport = new BytesWritable();
				Dport.set(value.getBytes(), 30, 2);
		
				BytesWritable pkt_byte = new BytesWritable();			
				pkt_byte.set(value.getBytes(), 20, 8);
		
				output.collect(Dport, pkt_byte);
			}
		}
		
	    public static class Port_Reduce extends MapReduceBase 
	    	implements Reducer<BytesWritable, BytesWritable, BytesWritable, BytesWritable> {
	        public void reduce(BytesWritable key, Iterator<BytesWritable> value,
	                        OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter)
	                        throws IOException {
	        	
	            byte[] sum = new byte[8];
	            byte[] bytes = new byte[8];
	            while(value.hasNext()){
	            	bytes = value.next().getBytes();        	
	            	sum = BitAdder.addBinary(sum, bytes, 8);
	            }
	            output.collect(key, new BytesWritable(sum));
	        }
	    }
	    
	    public static JobConf getConf(String jobName){
	    	
			JobConf conf = new JobConf(TestBinaryFlow.class);
			conf.setInt("io.file.buffer.size", DEFAULT_RECORD_SIZE);

	        conf.setJobName(jobName);
	        
	        conf.setInputFormat(BinaryInputFormat.class);
	        conf.setOutputFormat(BinaryOutputFormat.class);        
	 //       conf.setOutputFormat(TextOutputFormat.class); 
	        
	        conf.setOutputKeyClass(BytesWritable.class);
	        conf.setOutputValueClass(BytesWritable.class);
	        
	        conf.setMapperClass(BytePerDPort_Map.class);
	        conf.setCombinerClass(Port_Reduce.class);
	        conf.setReducerClass(Port_Reduce.class);	
	        return conf;
	    }
		/**
		 * @param args
		 */
		public static void main(String[] args) {
			// TODO Auto-generated method stub
			
			String inPathName = null;
			String outPathName = null;		
			String date = null;
			JobConf conf = getConf(args[0]);
			
			for(int i=1; i<28;i++){
				date = String.format("{0#}", String.valueOf(i));
				inPathName = "2010-02_bin/2010-02-" + date;
				outPathName = "2010-02_binRes/2010-02-" + date;
				
		        FileInputFormat.setInputPaths(conf, new Path(inPathName));
		        FileOutputFormat.setOutputPath(conf, new Path(outPathName));
		        
				try {
					JobClient.runJob(conf);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}  
			}
		}
		
		
}
