package nflow.runner;

import java.io.IOException;
import java.util.Iterator;

import org.apache.hadoop.fs.FileSystem;
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
import org.apache.hadoop.mapred.TextOutputFormat;

import p3.hadoop.common.util.BitAdder;
import p3.hadoop.io.ExtendedBytesWritable;
import p3.hadoop.mapred.BinaryInputFormat;
import p3.hadoop.mapred.BinaryOutputFormat;


public class TestBinaryFlow {

	private static final int DEFAULT_RECORD_SIZE = 34;
// 64M-> 67108864
//	private static final int DEFAULT_BINARY_BLOCK_SIZE = 67108860;
	
 	//Port
	public static class Dport_Map extends MapReduceBase 
	implements Mapper<BytesWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(BytesWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {

			byte[] value_bytes = value.getBytes();
			BytesWritable Dport = new BytesWritable();
			Dport.set(value_bytes, 30, 2);		

			ExtendedBytesWritable pkt_byte = new ExtendedBytesWritable(new byte[8]);	
			pkt_byte.set(value_bytes, 20, 4, 4);				
			
			BytesWritable PktBytes = new BytesWritable();
			PktBytes.set(pkt_byte.getBytes(), 0, 8);

			output.collect(Dport, PktBytes);
		}
	}
	
    public static class Port_Reduce extends MapReduceBase 
    	implements Reducer<BytesWritable, BytesWritable, BytesWritable, BytesWritable> {
        public void reduce(BytesWritable key, Iterator<BytesWritable> value,
                        OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter)
                        throws IOException {
 
            byte[] sum = new byte[8];
  		    byte[] data = new byte[8];  
			
			while(value.hasNext()){  	
	        	   data = value.next().getBytes();			 				
	        	   sum = BitAdder.addBinary(sum, data, 8);

			}
			output.collect(key, new BytesWritable(sum));                   
        }
    }
    
	//Port
	public static class Dport_Map2 extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {

			byte[] value_bytes = value.getBytes();
			BytesWritable Dport = new BytesWritable();
			Dport.set(value_bytes, 30, 2);
	
			ExtendedBytesWritable pkt_byte = new ExtendedBytesWritable(new byte[16]);	
			pkt_byte.set(value_bytes, 20, 4, 4);	
			pkt_byte.set(value_bytes, 24, 12, 4);				
			
			BytesWritable PktBytes = new BytesWritable();
			PktBytes.set(pkt_byte.getBytes(),0,16);
	
			output.collect(Dport, PktBytes);
		}
	}
	
    public static class Port_Reduce2 extends MapReduceBase 
    	implements Reducer<BytesWritable, BytesWritable, BytesWritable, BytesWritable> {
        public void reduce(BytesWritable key, Iterator<BytesWritable> value,
                        OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter)
                        throws IOException {
 
           byte[] sum = new byte[16];
 		   byte[] data = new byte[16];        	

           while(value.hasNext()){  
        	   data = value.next().getBytes();			 				
        	   sum = BitAdder.addBinary(sum, data, 16);
           }
           output.collect(key, new BytesWritable(sum));                   
        }
    }
    
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		JobConf conf = new JobConf(TestBinaryFlow.class);
		
		conf.setInt("io.file.buffer.size", DEFAULT_RECORD_SIZE);	
        conf.setJobName(args[1]);
        
        conf.setInputFormat(BinaryInputFormat.class);      
        conf.setOutputFormat(TextOutputFormat.class); 
//        conf.setOutputFormat(BinaryOutputFormat.class);
//        conf.setInputKeyClass(LongWritable.class);
//        conf.setInputValueClass(BytesWritable.class);
        conf.setOutputKeyClass(BytesWritable.class);
        conf.setOutputValueClass(BytesWritable.class);
                                        
        if(args[0].equals("One")) {
            conf.setMapperClass(Dport_Map.class);
            conf.setCombinerClass(Port_Reduce.class);
            conf.setReducerClass(Port_Reduce.class);     	
        }else if(args[0].equals("Two")){
            conf.setMapperClass(Dport_Map2.class);
            conf.setCombinerClass(Port_Reduce2.class);
            conf.setReducerClass(Port_Reduce2.class);       	
        }
         
        FileInputFormat.setInputPaths(conf, new Path(args[2]));
        FileOutputFormat.setOutputPath(conf, new Path("binRes"));
        
		try {
	        FileSystem fs = FileSystem.get(conf);
			// delete any output that might exist from a previous run of this job
	        if (fs.exists(FileOutputFormat.getOutputPath(conf))) {
	          fs.delete(FileOutputFormat.getOutputPath(conf), true);
	        }
	        
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		try {
			JobClient.runJob(conf);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
	}
}
