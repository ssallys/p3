package nflow.hadoop.flow.analyzer;


import java.io.IOException;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.compress.BZip2Codec;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reducer;
import org.apache.hadoop.mapred.Reporter;

public class TestCompressedWithNoThread {

	//Port
	public static class BytePerDPort_Map extends MapReduceBase implements Mapper<LongWritable, Text, LongWritable, LongWritable>{
		public void map
				(LongWritable key, Text value, 
				OutputCollector<LongWritable, LongWritable> output, Reporter reporter) throws IOException {
			String line = value.toString();
			boolean index_check = false;
			if(line.indexOf("Start") > -1){ index_check = true;}
			StringTokenizer tokenizer = new StringTokenizer(line);
			if(!index_check && tokenizer.hasMoreTokens()){
				for(int i = 0; i < 7; i++){
					tokenizer.nextToken();
				}
				long port_long = new Long(tokenizer.nextToken());
				for(int i = 0; i < 3;i++){
					tokenizer.nextToken();
				}
				long byte_count_long = new Long(tokenizer.nextToken());
				
				LongWritable port = new LongWritable(port_long);
				LongWritable byte_count = new LongWritable(byte_count_long);
				
				output.collect(port, byte_count);
			}
		}
	}
	
    public static class Port_Reduce extends MapReduceBase implements Reducer<LongWritable, LongWritable, LongWritable, LongWritable> {
        public void reduce(LongWritable key, Iterator<LongWritable> value,
                        OutputCollector<LongWritable, LongWritable> output, Reporter reporter)
                        throws IOException {
            long sum = 0;
            while(value.hasNext()){
                sum += value.next().get();
            }
            output.collect(key, new LongWritable(sum));
        }
    }

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		JobConf conf = new JobConf(thread_FlowAnalyzer.class);
		
        conf.setBoolean("mapred.output.compress", true);
        conf.setClass("mapred.output.compression.codec", BZip2Codec.class, CompressionCodec.class);
       
        conf.setJobName(args[0]);
        
        conf.setOutputKeyClass(LongWritable.class);
        conf.setOutputValueClass(LongWritable.class);
        
        conf.setMapperClass(BytePerDPort_Map.class);
        conf.setCombinerClass(Port_Reduce.class);
        conf.setReducerClass(Port_Reduce.class);
                                
        FileInputFormat.setInputPaths(conf, new Path(args[0]));
        FileOutputFormat.setOutputPath(conf, new Path("result/BytePerDPort"));
        
		try {
			JobClient.runJob(conf);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
	}

}
