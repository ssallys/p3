package nflow.hadoop.flow.analyzer;


import java.io.IOException;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.BZip2Codec;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;


public class Thread_CompressedFlowAnalyzer extends thread_FlowAnalyzer {

	public Thread_CompressedFlowAnalyzer(String JN, String dir) {
		super(JN, dir);
		// TODO Auto-generated constructor stub
	}
	
//	HashMap threadMap = new HashMap<String, WritableComparable>(); 
	//thread Runnable Function
	@Override
	public void run(){
		
		JobConf conf = new JobConf(thread_FlowAnalyzer.class);
		
        conf.setBoolean("mapred.output.compress", true);
        conf.setClass("mapred.output.compression.codec", BZip2Codec.class, CompressionCodec.class);
       
		if(sJobName.equals("byteperDport")){
			
            conf.setJobName(sJobName);
            
            conf.setOutputKeyClass(LongWritable.class);
            conf.setOutputValueClass(LongWritable.class);
            
            conf.setMapperClass(BytePerDPort_Map.class);
            conf.setCombinerClass(Port_Reduce.class);
            conf.setReducerClass(Port_Reduce.class);
                                    
            FileInputFormat.setInputPaths(conf, new Path(sDirectory));
            FileOutputFormat.setOutputPath(conf, new Path("result/BytePerDPort"));
        }
		else if(sJobName.equals("byteperSport")){
            conf.setJobName(sJobName);
            conf.setOutputKeyClass(LongWritable.class);
            conf.setOutputValueClass(LongWritable.class);
            conf.setMapperClass(BytePerSPort_Map.class);
            conf.setCombinerClass(Port_Reduce.class);
            conf.setReducerClass(Port_Reduce.class);

            FileInputFormat.setInputPaths(conf, new Path(sDirectory));
            FileOutputFormat.setOutputPath(conf, new Path("result/BytePerSPort"));
        }
		else if(sJobName.equals("packetperDport")){
            conf.setJobName(sJobName);
            conf.setOutputKeyClass(LongWritable.class);
            conf.setOutputValueClass(LongWritable.class);
            conf.setMapperClass(PacketPerDPort_Map.class);
            conf.setCombinerClass(Port_Reduce.class);
            conf.setReducerClass(Port_Reduce.class);

            FileInputFormat.setInputPaths(conf, new Path(sDirectory));
            FileOutputFormat.setOutputPath(conf, new Path("result/PacketPerDPort"));
        }
		else if(sJobName.equals("packetperSport")){
            conf.setJobName(sJobName);
            conf.setOutputKeyClass(LongWritable.class);
            conf.setOutputValueClass(LongWritable.class);
            conf.setMapperClass(PacketPerSPort_Map.class);
            conf.setCombinerClass(Port_Reduce.class);
            conf.setReducerClass(Port_Reduce.class);
            
            FileInputFormat.setInputPaths(conf, new Path(sDirectory));
            FileOutputFormat.setOutputPath(conf, new Path("result/PacketPerSPort"));
        }
		else if(sJobName.equals("byteperDip")){
			conf.setJobName(sJobName);
			conf.setOutputKeyClass(Text.class);
			conf.setOutputValueClass(LongWritable.class);
			conf.setMapperClass(BytePerDIP_Map.class);
			conf.setCombinerClass(IP_Reduce.class);
			conf.setReducerClass(IP_Reduce.class);
			
			FileInputFormat.setInputPaths(conf, new Path(sDirectory));
			FileOutputFormat.setOutputPath(conf, new Path("result/BytePerDIP"));
		}
		else if(sJobName.equals("byteperSip")){
            conf.setJobName(sJobName);
            conf.setOutputKeyClass(Text.class);
            conf.setOutputValueClass(LongWritable.class);
            conf.setMapperClass(BytePerSIP_Map.class);
            conf.setCombinerClass(IP_Reduce.class);
            conf.setReducerClass(IP_Reduce.class);
            FileInputFormat.setInputPaths(conf, new Path(sDirectory));
            FileOutputFormat.setOutputPath(conf, new Path("result/BytePerSIP"));
        }
		else if(sJobName.equals("packetperDip")){
            conf.setJobName(sJobName);
            conf.setOutputKeyClass(Text.class);
            conf.setOutputValueClass(LongWritable.class);
            conf.setMapperClass(PacketPerDIP_Map.class);
            conf.setCombinerClass(IP_Reduce.class);
            conf.setReducerClass(IP_Reduce.class);

            FileInputFormat.setInputPaths(conf, new Path(sDirectory));
            FileOutputFormat.setOutputPath(conf, new Path("result/PacketPerDIP"));
        }
		else if(sJobName.equals("packetperSip")){
            conf.setJobName(sJobName);
            conf.setOutputKeyClass(Text.class);
            conf.setOutputValueClass(LongWritable.class);
            conf.setMapperClass(PacketPerSIP_Map.class);
            conf.setCombinerClass(IP_Reduce.class);
            conf.setReducerClass(IP_Reduce.class);
            
            FileInputFormat.setInputPaths(conf, new Path(sDirectory));
            FileOutputFormat.setOutputPath(conf, new Path("result/PacketPerSIP"));
        }
		try{
		JobClient.runJob(conf);
		}
		catch (IOException e){}
	}

}
