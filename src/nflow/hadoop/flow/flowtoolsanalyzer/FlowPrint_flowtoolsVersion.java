package nflow.hadoop.flow.flowtoolsanalyzer;

import java.io.IOException;
import java.util.Iterator;
import nflow.runner.TestBinaryFlow;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
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

import p3.hadoop.common.util.EZBytes;
import p3.hadoop.mapred.BinaryInputFormat;

/**
 * NetFlow Ver.5 Packet Analysis
 * @author yhlee
 *
 */
public class FlowPrint_flowtoolsVersion {
	
	JobConf conf;
	EZBytes eb;

	public FlowPrint_flowtoolsVersion(JobConf conf){
		this.conf = conf;
	}
	
	public static class Map extends MapReduceBase 
	implements Mapper<BytesWritable, BytesWritable, NullWritable, FlowWritable_flowtoolsVersion>{
		public void map
				(BytesWritable key, BytesWritable value, 
				OutputCollector<NullWritable, FlowWritable_flowtoolsVersion> output, Reporter reporter) throws IOException {		
			
			byte[] value_bytes = value.getBytes();
			FlowWritable_flowtoolsVersion fw = new FlowWritable_flowtoolsVersion();
			if(value_bytes.length < DEFAULT_RECORD_SIZE) return;	
			try{
				if(fw.parse(value_bytes)){
					output.collect(NullWritable.get(), fw);					
				}else{
//					reporter.incrCounter(COUNTER_KEYS.INVALID_LINES, 1);	
				}
			} catch (NumberFormatException e) {					
		  
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

    public static class Reduce extends MapReduceBase 
    	implements Reducer<NullWritable, FlowWritable_flowtoolsVersion, NullWritable, FlowWritable_flowtoolsVersion> {
        public void reduce(NullWritable key, Iterator<FlowWritable_flowtoolsVersion> value,
                        OutputCollector<NullWritable, FlowWritable_flowtoolsVersion> output, Reporter reporter)
                        throws IOException {

        	FlowWritable_flowtoolsVersion fw;
			
        	while(value.hasNext()){  
        		fw = value.next();
                output.collect(NullWritable.get(), fw);   
           }                
        }
    }
    
	private static final int DEFAULT_RECORD_SIZE = 34;
	private static final int FULL_RECORD_SIZE = 64;
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		JobConf conf = new JobConf(TestBinaryFlow.class);
		
		conf.setInt("io.file.buffer.size", FULL_RECORD_SIZE);	
        conf.setJobName(args[0]);
        
        conf.setInputFormat(BinaryInputFormat.class);      
        conf.setOutputFormat(TextOutputFormat.class); 
        
        conf.setOutputKeyClass(NullWritable.class);
        conf.setOutputValueClass(FlowWritable_flowtoolsVersion.class);                                      
        conf.setMapperClass(Map.class);

/*        
        conf.setOutputKeyClass(BytesWritable.class);
        conf.setOutputValueClass(BytesWritable.class);
        conf.setMapperClass(Iden_Map.class); 	
*/         
        FileInputFormat.setInputPaths(conf, new Path(args[0]));
        FileOutputFormat.setOutputPath(conf, new Path("flow_print"));
        
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
