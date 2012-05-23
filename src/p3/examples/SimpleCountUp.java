package p3.examples;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Calendar;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
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

import p3.hadoop.common.packet.PcapRec;
import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.common.util.CommonData;
import p3.hadoop.mapred.PcapInputFormat;

/**
 * 
 * @author yhlee in Chungnam National University
 *  ssallys@naver.com
 */
public class SimpleCountUp {

	private static final int MIN_PKT_SIZE = 42;
		
	public static boolean isFilter = false;
	public JobConf conf;

	public static class Filter{ 
		static int net = -1;	
		static int port = -1;
		static int proto = -1;
		
		public static int getNet() {
			return net;
		}
		public static void setNet(int net) {
			Filter.net = net;
		}
		public static int getPort() {
			return port;
		}
		public static void setPort(int port) {
			Filter.port = port;
		}
		public static int getProto() {
			return proto;
		}
		public static void setProto(int proto) {
			Filter.proto = proto;
		}
	}
	
	public SimpleCountUp(){
		conf = new JobConf(SimpleCountUp.class);
		conf.addResource("p3-default.xml");
	}
	
	public SimpleCountUp(JobConf conf){
		this.conf = conf;
	}
	
    /*******************************************
		TOP N function
	*******************************************/
	
	public static class Map_TopN extends MapReduceBase 
	implements Mapper<LongWritable, Text, Text, Text>{
	
		int key_field = 0;		
		public void configure(JobConf conf){
			key_field = conf.getInt("pcap.record.sort.field", 1);		
		}
	
		public void map
				(LongWritable key, Text value, 
				OutputCollector<Text, Text> output, Reporter reporter) throws IOException {		
			
			String line = value.toString(); 	  	
			String tokens[] = line.split(" ");
			String new_key = tokens[key_field];
			
			output.collect(new Text(new_key), value);	
		}
	}
	
	public static class Reduce_TopN extends MapReduceBase 
	implements Reducer<Text, Text, Text, Text> {
	
		long topN = 0;
		public void configure(JobConf conf){
			topN = conf.getLong("pcap.record.sort.topN", 4294967295L);		
		}
		
		public void reduce(Text key, Iterator<Text> value,
		                OutputCollector<Text, Text> output, Reporter reporter)
		                throws IOException {
			
		   int cnt = 0;				          
		   while(value.hasNext()){  
		       if (cnt<topN){
			       output.collect(key, value.next());	  
			       cnt++;
		       }
		   }	  
		}
	}      
	
	private JobConf getTopNJobConf(String jobName, Path inFilePath, Path outFilePath){
	
		JobConf conf = new JobConf(SimpleCountUp.class);
		
		conf.addResource("p3-default.xml");
		conf.setInt("pcap.record.rate.interval", this.conf.getInt("pcap.record.rate.interval", 60));
		conf.setInt("pcap.record.key.pos", this.conf.getInt("pcap.record.key.pos", PcapRec.POS_SIP));
		conf.setInt("pcap.record.key.len", this.conf.getInt("pcap.record.key.len", PcapRec.LEN_IPADDR));
		conf.setInt("pcap.record.sort.field", this.conf.getInt("pcap.record.sort.field", 1));
		
		conf.setJobName(jobName); 
		conf.setNumReduceTasks(1);
		conf.setOutputKeyClass(Text.class);
		conf.setOutputValueClass(Text.class);	       
		conf.setInputFormat(TextInputFormat.class);            
		conf.setOutputFormat(TextOutputFormat.class);  
		conf.setMapperClass(Map_TopN.class);
		conf.setCombinerClass(Reduce_TopN.class);
		conf.setReducerClass(Reduce_TopN.class);    
		
		FileInputFormat.setInputPaths(conf, inFilePath);
		FileOutputFormat.setOutputPath(conf, outFilePath);
		
		return conf;
	}   


    /*******************************************
				COUNT function
	*******************************************/
	
	public static class Map_CountUp extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, Text, Text>{
		int key_len = 0;
		int key_pos = 0;
		
		public void configure(JobConf conf){
			key_len = conf.getInt("pcap.record.key.len", PcapRec.LEN_IPADDR);
			key_pos = conf.getInt("pcap.record.key.pos", PcapRec.POS_SIP);			
		}
		
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<Text, Text> output, Reporter reporter) throws IOException {		
		
			byte[] eth_type = new byte[2];
			byte[] ip_ver = {0x00};	
			byte[] new_key = new byte[key_len];
			byte[] value_bytes = value.getBytes();	
			byte[] bc = new byte[4];
			String strKey = null;
			
			if(value_bytes.length<MIN_PKT_SIZE) return;			
			System.arraycopy(value_bytes, PcapRec.POS_ETH_TYPE, eth_type, 0, PcapRec.LEN_ETH_TYPE);
			
			/* ip */
			if(BinaryUtils.byteToInt(eth_type) == PcapRec.IP_PROTO) {			
				System.arraycopy(value_bytes, PcapRec.POS_IP_VER, ip_ver, 0, PcapRec.LEN_IP_VER);
				
				/* ipv4 */				
				if((BinaryUtils.byteToInt(ip_ver) & PcapRec.IPV4) == PcapRec.IPV4){
					System.arraycopy(value_bytes, key_pos, new_key, 0, new_key.length);	
					System.arraycopy(value_bytes, PcapRec.POS_IP_BYTES, bc,0, PcapRec.LEN_IP_BYTES); // set byte count
					
					if (new_key.length==4) 
						strKey = CommonData.longTostrIp(Bytes.toLong(new_key));
					else
						strKey = Long.toString(Bytes.toLong(new_key));
					
					output.collect(new Text(strKey), new Text(Bytes.toInt(bc)+" "+1));					
				}				
			}
		}
	}
		
    public static class Reduce_CountUp extends MapReduceBase 
	implements Reducer<Text, Text, Text, Text> {
        public void reduce(Text key, Iterator<Text> value,
                        OutputCollector<Text, Text> output, Reporter reporter)
                        throws IOException {

			String line = null;
			long bc = 0;
			long pc = 0;
			
			StringTokenizer token;

           while(value.hasNext()){  
        	   line = value.next().toString();	
        	   token = new StringTokenizer(line);
	    	   if(line.length()<0)  continue;		       
		       bc += Long.parseLong(token.nextToken().trim());
		       pc += Long.parseLong(token.nextToken().trim());
           }
           output.collect(key, new Text(Long.toString(bc)+" "+Long.toString(pc)));                   
        }
    }
       
	private JobConf getCountUpJobConf(String jobName, Path inFilePath, Path outFilePath){
		
	    Path Output = new Path(jobName);			
        conf.setJobName(jobName);     
        conf.setNumReduceTasks(10);       
        conf.setOutputKeyClass(Text.class);
        conf.setOutputValueClass(Text.class);	       
        conf.setInputFormat(PcapInputFormat.class);        
        conf.setOutputFormat(TextOutputFormat.class);        
        conf.setMapperClass(Map_CountUp.class);
        conf.setCombinerClass(Reduce_CountUp.class);          
        conf.setReducerClass(Reduce_CountUp.class);    
        
        FileInputFormat.setInputPaths(conf, inFilePath);
        FileOutputFormat.setOutputPath(conf, Output);
        
        return conf;
	}
    
    public void startCount(Path inputDir, Path outputDir, long cap_start, long cap_end){// throws IOException {
        
	try {
		FileSystem fs = FileSystem.get(conf);
        JobConf countJobconf = getCountUpJobConf("CountUp", inputDir, outputDir);        
        countJobconf.setLong("pcap.file.captime.min", cap_start);
        countJobconf.setLong("pcap.file.captime.max", cap_end);
        
        // delete any output that might exist from a previous run of this job
        if (fs.exists(FileOutputFormat.getOutputPath(countJobconf))) {
          fs.delete(FileOutputFormat.getOutputPath(countJobconf), true);
        }        
		JobClient.runJob(countJobconf);	
		
		if(conf.getInt("pcap.record.sort.field", 0) > 0){
	        Path countOutputDir = FileOutputFormat.getOutputPath(countJobconf);
	        JobConf sortJobConf = getTopNJobConf("TopN", countOutputDir, outputDir);  
	        
	        // delete any output that might exist from a previous run of this job
	        if (fs.exists(FileOutputFormat.getOutputPath(sortJobConf))) {
	          fs.delete(FileOutputFormat.getOutputPath(sortJobConf), true);
	        }
	        JobClient.runJob(sortJobConf);		
		}
		
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
  }
    
	private static final int PCAP_FILE_HEADER_LENGTH = 24;  
	private static final int ONEDAYINSEC = 432000;
	
	public static void main(String[] args) throws Exception{
	
		String srcFilename = new String();   		
		boolean fh_skip = true;
		long cap_start = Long.MAX_VALUE;
		long cap_end = Long.MIN_VALUE;
		char argtype = 0;
		
		SimpleCountUp cu = new SimpleCountUp();
		
		cu.conf.addResource("p3-default.xml");
		
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
		FileSystem fs = FileSystem.get(URI.create(srcFilename), cu.conf);
		InputStream in = null;
	    byte[] buffer = new byte[PCAP_FILE_HEADER_LENGTH];
		long timestamp = 0;
		
		if(cap_start == Long.MAX_VALUE){
			FileStatus stat = fs.getFileStatus(inputPath);
			if(stat.isDir()){
				FileStatus[] stats = fs.listStatus(inputPath);
				for(FileStatus curfs : stats){
					if(!curfs.isDir()){
						System.out.println(curfs.getPath());
						in = fs.open(curfs.getPath());
						if(fh_skip)
							in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
						in.read(buffer, 0, 4);
						timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
						if(timestamp < cap_start)
							cap_start = timestamp;
						if(timestamp > cap_end)
							cap_end = timestamp;
					}
				}
				in.close();
				fs.close();
				cap_end = cap_end + ONEDAYINSEC;
			}else{
				in = fs.open(inputPath);
				if(fh_skip)
					in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
				in.read(buffer, 0, 4);
				timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
				System.out.println(timestamp);
				cap_start = timestamp;
				
				if(cap_end == Long.MIN_VALUE){
					cap_end = cap_start+ONEDAYINSEC;
				}
				in.close();
				fs.close();
			}				
		}
	
		if(cap_end == Long.MIN_VALUE)
			cap_end = cap_start+ONEDAYINSEC;
		
		cu.startCount(inputPath, outputPath, cap_start, cap_end);	
	}
}
