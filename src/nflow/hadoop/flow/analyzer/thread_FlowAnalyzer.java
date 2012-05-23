package nflow.hadoop.flow.analyzer;


import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
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
import org.apache.hadoop.util.*;

import p3.hadoop.mapred.*;

public class thread_FlowAnalyzer extends Thread{
	public String sJobName = null;
	public String sDirectory = null;

	public thread_FlowAnalyzer(String JN, String dir){
		sJobName = JN;
		sDirectory = dir;
	}

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
    public static class PacketPerDPort_Map extends MapReduceBase implements Mapper<LongWritable, Text, LongWritable, LongWritable>{
            public void map(LongWritable key, Text value, OutputCollector<LongWritable, LongWritable> output, Reporter reporter) throws IOException {
                    String line = value.toString();
                    boolean index_check = false;
                    if(line.indexOf("Start") > -1){ index_check = true;}
                    StringTokenizer tokenizer = new StringTokenizer(line);
                    if(!index_check && tokenizer.hasMoreTokens()){
                            for(int i = 0; i < 7; i++){
                                    tokenizer.nextToken();
                            }
                            long port_long = new Long(tokenizer.nextToken());
                            for(int i = 0; i < 2;i++){
                                    tokenizer.nextToken();
                            }
                            long packet_count_long = new Long(tokenizer.nextToken());

                            LongWritable port = new LongWritable(port_long);
                            LongWritable packet_count = new LongWritable(packet_count_long);

                            output.collect(port, packet_count);
                    }                                
            }
    }
    public static class BytePerSPort_Map extends MapReduceBase implements Mapper<LongWritable, Text, LongWritable, LongWritable>{
            public void map
                            (LongWritable key, Text value,
                            OutputCollector<LongWritable, LongWritable> output, Reporter reporter) throws IOException {
                    String line = value.toString();
                    boolean index_check = false;
                    if(line.indexOf("Start") > -1){ index_check = true;}
                    StringTokenizer tokenizer = new StringTokenizer(line);
                    if(!index_check && tokenizer.hasMoreTokens()){
                            for(int i = 0; i < 4; i++){
                                    tokenizer.nextToken();
                            }
                            long port_long = new Long(tokenizer.nextToken());
                            for(int i = 0; i < 6;i++){
                                    tokenizer.nextToken();
                            }
                            long byte_count_long = new Long(tokenizer.nextToken());

                            LongWritable port = new LongWritable(port_long);
                            LongWritable byte_count = new LongWritable(byte_count_long);

                            output.collect(port, byte_count);
                    }
            }
    }
    public static class PacketPerSPort_Map extends MapReduceBase implements Mapper<LongWritable, Text, LongWritable, LongWritable>{
            public void map(LongWritable key, Text value, OutputCollector<LongWritable, LongWritable> output, Reporter reporter) throws IOException {
                    String line = value.toString();
                    boolean index_check = false;
                    if(line.indexOf("Start") > -1){ index_check = true;}
                    StringTokenizer tokenizer = new StringTokenizer(line);
                    if(!index_check && tokenizer.hasMoreTokens()){
                            for(int i = 0; i < 4; i++){
                                    tokenizer.nextToken();
                            }
                            long port_long = new Long(tokenizer.nextToken());
                            for(int i = 0; i < 5;i++){
                                    tokenizer.nextToken();
                            }
                            long packet_count_long = new Long(tokenizer.nextToken());

                            LongWritable port = new LongWritable(port_long);
                            LongWritable packet_count = new LongWritable(packet_count_long);

                            output.collect(port, packet_count);
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
	public static class Port_top10_Reduce extends MapReduceBase implements Reducer<LongWritable, LongWritable, LongWritable, LongWritable> {
                public void reduce(LongWritable key, Iterator<LongWritable> value,
                                OutputCollector<LongWritable, LongWritable> output, Reporter reporter)
                                throws IOException {
                        long sum = 0;
                        while(value.hasNext()){
                                sum += value.next().get();
                        }
                        output.collect(new LongWritable(sum), key);
                }

        }

	//IP Address
	public static class BytePerDIP_Map extends MapReduceBase implements Mapper<LongWritable, Text, Text, LongWritable>{
                public void map
                                (LongWritable key, Text value,
                                OutputCollector<Text, LongWritable> output, Reporter reporter) throws IOException {
                        String line = value.toString();
                        boolean index_check = false;
                        if(line.indexOf("Start") > -1){ index_check = true;}
                        StringTokenizer tokenizer = new StringTokenizer(line);
                        if(!index_check && tokenizer.hasMoreTokens()){
                                for(int i = 0; i < 6; i++){
                                        tokenizer.nextToken();
                                }
				Text ip_address = new Text();
                                ip_address.set(tokenizer.nextToken());
                                for(int i = 0; i < 4;i++){
                                        tokenizer.nextToken();
                                }
                                long byte_count_long = new Long(tokenizer.nextToken());

                                LongWritable byte_count = new LongWritable(byte_count_long);

                                output.collect(ip_address, byte_count);
                        }
                }
        }
	public static class BytePerSIP_Map extends MapReduceBase implements Mapper<LongWritable, Text, Text, LongWritable>{
                public void map
                                (LongWritable key, Text value,
                                OutputCollector<Text, LongWritable> output, Reporter reporter) throws IOException {
                        String line = value.toString();
                        boolean index_check = false;
                        if(line.indexOf("Start") > -1){ index_check = true;}
                        StringTokenizer tokenizer = new StringTokenizer(line);
                        if(!index_check && tokenizer.hasMoreTokens()){
                                for(int i = 0; i < 3; i++){
                                        tokenizer.nextToken();
                                }
                                Text ip_address = new Text();
                                ip_address.set(tokenizer.nextToken());
                                for(int i = 0; i < 7;i++){
                                        tokenizer.nextToken();
                                }
                                long byte_count_long = new Long(tokenizer.nextToken());

                                LongWritable byte_count = new LongWritable(byte_count_long);

                                output.collect(ip_address, byte_count);
                        }
                }
        }
	public static class PacketPerDIP_Map extends MapReduceBase implements Mapper<LongWritable, Text, Text, LongWritable>{
                public void map
                                (LongWritable key, Text value,
                                OutputCollector<Text, LongWritable> output, Reporter reporter) throws IOException {
                        String line = value.toString();
                        boolean index_check = false;
                        if(line.indexOf("Start") > -1){ index_check = true;}
                        StringTokenizer tokenizer = new StringTokenizer(line);
                        if(!index_check && tokenizer.hasMoreTokens()){
                                for(int i = 0; i < 6; i++){
                                        tokenizer.nextToken();
                                }
                                Text ip_address = new Text();
                                ip_address.set(tokenizer.nextToken());
                                for(int i = 0; i < 3;i++){
                                        tokenizer.nextToken();
                                }
                                long byte_count_long = new Long(tokenizer.nextToken());

                                LongWritable byte_count = new LongWritable(byte_count_long);

                                output.collect(ip_address, byte_count);
                        }
                }
        }
	public static class PacketPerSIP_Map extends MapReduceBase implements Mapper<LongWritable, Text, Text, LongWritable>{
                public void map
                                (LongWritable key, Text value,
                                OutputCollector<Text, LongWritable> output, Reporter reporter) throws IOException {
                        String line = value.toString();
                        boolean index_check = false;
                        if(line.indexOf("Start") > -1){ index_check = true;}
                        StringTokenizer tokenizer = new StringTokenizer(line);
                        if(!index_check && tokenizer.hasMoreTokens()){
                                for(int i = 0; i < 3; i++){
                                        tokenizer.nextToken();
                                }
                                Text ip_address = new Text();
                                ip_address.set(tokenizer.nextToken());
                                for(int i = 0; i < 6;i++){
                                        tokenizer.nextToken();
                                }
                                long byte_count_long = new Long(tokenizer.nextToken());

                                LongWritable byte_count = new LongWritable(byte_count_long);

                                output.collect(ip_address, byte_count);
                        }
                }
        }
	public static class IP_Reduce extends MapReduceBase implements Reducer<Text, LongWritable, Text, LongWritable> {
                public void reduce(Text key, Iterator<LongWritable> value,
                                OutputCollector<Text, LongWritable> output, Reporter reporter)
                                throws IOException {
                        long sum = 0;
                        while(value.hasNext()){
                                sum += value.next().get();
                        }
                        output.collect(key, new LongWritable(sum));
                }

        }
	
	//thread Runnable Function
	public void run(){
		JobConf conf = new JobConf(thread_FlowAnalyzer.class);
		if(sJobName.equals("byteperDport")){
			
                        conf.setJobName(sJobName);
                        conf.setOutputKeyClass(LongWritable.class);
                        conf.setOutputValueClass(LongWritable.class);
                        
                        conf.setMapperClass(BytePerDPort_Map.class);
                        conf.setCombinerClass(Port_Reduce.class);
                        conf.setReducerClass(Port_Reduce.class);
                        
                        conf.setInputFormat(TextInputFormat.class);
                        conf.setOutputFormat(TextOutputFormat.class);
                        
                        FileInputFormat.setInputPaths(conf, new Path(sDirectory));
                        FileOutputFormat.setOutputPath(conf, new Path("txtRes/BytePerDPort"));
                }
		else if(sJobName.equals("byteperSport")){
                        conf.setJobName(sJobName);
                        conf.setOutputKeyClass(LongWritable.class);
                        conf.setOutputValueClass(LongWritable.class);
                        conf.setMapperClass(BytePerSPort_Map.class);
                        conf.setCombinerClass(Port_Reduce.class);
                        conf.setReducerClass(Port_Reduce.class);
                        conf.setInputFormat(TextInputFormat.class);
                        conf.setOutputFormat(TextOutputFormat.class);
                        FileInputFormat.setInputPaths(conf, new Path(sDirectory));
                        FileOutputFormat.setOutputPath(conf, new Path("txtRes/BytePerSPort"));
                }
		else if(sJobName.equals("packetperDport")){
                        conf.setJobName(sJobName);
                        conf.setOutputKeyClass(LongWritable.class);
                        conf.setOutputValueClass(Text.class);
                        conf.setMapperClass(PacketPerDPort_Map.class);
                        conf.setCombinerClass(Port_Reduce.class);
                        conf.setReducerClass(Port_Reduce.class);
                        conf.setInputFormat(TextInputFormat.class);
                        conf.setOutputFormat(TextOutputFormat.class);
                        FileInputFormat.setInputPaths(conf, new Path(sDirectory));
                        FileOutputFormat.setOutputPath(conf, new Path("txtRes/PacketPerDPort"));
                }
		else if(sJobName.equals("packetperSport")){
                        conf.setJobName(sJobName);
                        conf.setOutputKeyClass(LongWritable.class);
                        conf.setOutputValueClass(LongWritable.class);
                        conf.setMapperClass(PacketPerSPort_Map.class);
                        conf.setCombinerClass(Port_Reduce.class);
                        conf.setReducerClass(Port_Reduce.class);
                        conf.setInputFormat(TextInputFormat.class);
                        conf.setOutputFormat(TextOutputFormat.class);
                        FileInputFormat.setInputPaths(conf, new Path(sDirectory));
                        FileOutputFormat.setOutputPath(conf, new Path("txtRes/PacketPerSPort"));
                }
		else if(sJobName.equals("byteperDip")){
			conf.setJobName(sJobName);
			conf.setOutputKeyClass(Text.class);
			conf.setOutputValueClass(LongWritable.class);
			conf.setMapperClass(BytePerDIP_Map.class);
			conf.setCombinerClass(IP_Reduce.class);
			conf.setReducerClass(IP_Reduce.class);
			conf.setInputFormat(TextInputFormat.class);
			conf.setOutputFormat(TextOutputFormat.class);
			FileInputFormat.setInputPaths(conf, new Path(sDirectory));
			FileOutputFormat.setOutputPath(conf, new Path("txtRes/BytePerDIP"));
		}
		else if(sJobName.equals("byteperSip")){
                        conf.setJobName(sJobName);
                        conf.setOutputKeyClass(Text.class);
                        conf.setOutputValueClass(LongWritable.class);
                        conf.setMapperClass(BytePerSIP_Map.class);
                        conf.setCombinerClass(IP_Reduce.class);
                        conf.setReducerClass(IP_Reduce.class);
                        conf.setInputFormat(TextInputFormat.class);
                        conf.setOutputFormat(TextOutputFormat.class);
                        FileInputFormat.setInputPaths(conf, new Path(sDirectory));
                        FileOutputFormat.setOutputPath(conf, new Path("txtRes/BytePerSIP"));
                }
		else if(sJobName.equals("packetperDip")){
                        conf.setJobName(sJobName);
                        conf.setOutputKeyClass(Text.class);
                        conf.setOutputValueClass(LongWritable.class);
                        conf.setMapperClass(PacketPerDIP_Map.class);
                        conf.setCombinerClass(IP_Reduce.class);
                        conf.setReducerClass(IP_Reduce.class);
                        conf.setInputFormat(TextInputFormat.class);
                        conf.setOutputFormat(TextOutputFormat.class);
                        FileInputFormat.setInputPaths(conf, new Path(sDirectory));
                        FileOutputFormat.setOutputPath(conf, new Path("txtRes/PacketPerDIP"));
                }
		else if(sJobName.equals("packetperSip")){
                        conf.setJobName(sJobName);
                        conf.setOutputKeyClass(Text.class);
                        conf.setOutputValueClass(LongWritable.class);
                        conf.setMapperClass(PacketPerSIP_Map.class);
                        conf.setCombinerClass(IP_Reduce.class);
                        conf.setReducerClass(IP_Reduce.class);
                        conf.setInputFormat(TextInputFormat.class);
                        conf.setOutputFormat(TextOutputFormat.class);
                        FileInputFormat.setInputPaths(conf, new Path(sDirectory));
                        FileOutputFormat.setOutputPath(conf, new Path("txtRes/PacketPerSIP"));
                }
		try{
		JobClient.runJob(conf);
		}
		catch (IOException e){}		
	}
}
