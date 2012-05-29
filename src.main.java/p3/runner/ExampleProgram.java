package p3.runner;



import java.io.IOException;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.hadoop.conf.Configuration;
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

import p3.common.lib.BinaryUtils;
import p3.common.lib.BitAdder;
import p3.common.lib.Bytes;
import p3.common.lib.CommonData;
import p3.hadoop.common.pcap.lib.ExtendedBytesWritable;
import p3.hadoop.mapred.BinaryInputFormat;
import p3.hadoop.mapred.BinaryOutputFormat;
import p3.hadoop.mapred.PcapInputFormat;

/**
 * NetFlow Ver.5 Packet Analysis
 * @author yhlee
 *
 */
public class ExampleProgram {

	private static int interval=60;
	private static int topN = 5;
	private static String sort_key="bc" ;
	
	public static boolean isFilter = false;
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
/*		
		public static boolean filt_port(){
			return 
		}
		*/
	}
	
	private static Configuration conf = new Configuration();

	static class Pcap{
		private static final int IP_PROTO = 0x0800;		
		private static final int IPV4 = 0x40;		
		private static final int UDP = 0x11;	
		private static final int TCP = 0x06;	
		
		private static final int POS_ETH_TYPE = 28;
		private static final int LEN_ETH_TYPE = 2;
		private static final int POS_IP_VER = 30;	
		private static final int LEN_IP_VER = 1;
		
		private static final int POS_IP_BYTES = 32;
		private static final int POS_IPV6_BYTES = 34;		
		private static final int LEN_IP_BYTES = 2;
		
		private static final int POS_SIP = 42;
		private static final int POS_DIP = 46;
//		private static final int POS_SN = 0;
		private static final int POS_PT = 39;
		private static final int POS_SP = 50;
		private static final int POS_DP = 52;
		
		private static final int POS_TSTMP = 0;
		
		//-----------------------------------//
		private static final int LEN_VAL1 = 4;	
		private static final int POS_VAL = 2;
		
		private static final int LEN_VAL2 = LEN_VAL1*2;
		private static final int LEN_VAL3 = LEN_VAL1*3;	
		private static final int POS_V_BC = POS_VAL;		
		private static final int POS_V_PC = LEN_VAL1+POS_VAL;
//		private static final int POS_V_FC = LEN_VAL2+POS_VAL;
	}

	private static final int FLOW_RECORD_SIZE = 17+Pcap.LEN_VAL3;
	private static final int MIN_PKT_SIZE = 16;
	
	public ExampleProgram(){
//	    this.conf = new Configuration();
	}
	
	public ExampleProgram(int interval){
	    super();
	    int i=0;	    
//		while(interval/Math.pow(2, i)>1)
//			HCoralProgram.interval_mask = (interval_mask<<1) & 0;
		
	    ExampleProgram.interval = (int)Math.pow(2, i);
	}	

    /*******************************************
				COUNT function
	*******************************************/
	
	public static class Map_CountUp extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
		
		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
		
			byte[] eth_type = new byte[2];
			byte[] ip_ver = {0x00};	
			
			byte[] value_bytes = value.getBytes();		
			if(value_bytes.length<MIN_PKT_SIZE) return;
			
			System.arraycopy(value_bytes, Pcap.POS_ETH_TYPE, eth_type, 0, Pcap.LEN_ETH_TYPE);
			
			/* ip */
			if(BinaryUtils.byteToInt(eth_type) == Pcap.IP_PROTO) {			
				System.arraycopy(value_bytes, Pcap.POS_IP_VER, ip_ver, 0, Pcap.LEN_IP_VER);
				
				/* ipv4 */				
				if((BinaryUtils.byteToInt(ip_ver) & Pcap.IPV4) == Pcap.IPV4){
					
					ExtendedBytesWritable new_key = new ExtendedBytesWritable(new byte[conf.getInt("count_len", 1)]);
					new_key.set(value_bytes, conf.getInt("count_pos", Pcap.POS_PT), 0, 1);	
					
					byte[] cntval = {0x01}; 									
					ExtendedBytesWritable new_value = new ExtendedBytesWritable(new byte[16]);	
					new_value.set(value_bytes, Pcap.POS_IP_BYTES, 6, Pcap.LEN_IP_BYTES);
					new_value.set(cntval, 0, 15, 1);	
					
					output.collect(new BytesWritable(new_key.getBytes()), new BytesWritable(new_value.getBytes()));					
				}				
			}
		}
	}
		
    public static class Reduce_CountUp extends MapReduceBase 
	implements Reducer<BytesWritable, BytesWritable, BytesWritable, BytesWritable> {
        public void reduce(BytesWritable key, Iterator<BytesWritable> value,
                        OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter)
                        throws IOException {
 
           byte[] sum = new byte[16];
 		   byte[] data = new byte[16]; 
 		  ExtendedBytesWritable new_key = new ExtendedBytesWritable(new byte[conf.getInt("count_len", 1)]);
 		  new_key.set(key.getBytes(), 0, 0, conf.getInt("count_len", 1));

           while(value.hasNext()){  
        	   data = value.next().getBytes();			 				
        	   sum = BitAdder.addBinary(sum, data, 16);
           }
           ExtendedBytesWritable new_value = new ExtendedBytesWritable(new byte[16]);
//           new_value.set(key.getBytes(), 0, 0, conf.getInt("count_len", 1));
           new_value.set(sum, 0, 0,sum.length); 
           output.collect(new BytesWritable(new_key.getBytes()), new BytesWritable(new_value.getBytes()));                   
        }
    }
    
	public static class Map_CountSort extends MapReduceBase 
	implements Mapper<BytesWritable, BytesWritable, BytesWritable, BytesWritable>{
		
		public void map
				(BytesWritable key, BytesWritable value, 
				OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		

			byte[] value_bytes = value.getBytes();		

			ExtendedBytesWritable new_key = new ExtendedBytesWritable(new byte[8]);
			new_key.set(value_bytes, 1, 0, 8);	
								
			ExtendedBytesWritable new_value = new ExtendedBytesWritable(new byte[18]);	
			new_value.set(value_bytes, 0, 0, new_value.getLength());	
			
			output.collect(new BytesWritable(new_key.getBytes()), new BytesWritable(new_value.getBytes()));					
		}
	}
		
    public static class Reduce_CountSort extends MapReduceBase 
	implements Reducer<BytesWritable, BytesWritable, BytesWritable, BytesWritable> {
        public void reduce(BytesWritable key, Iterator<BytesWritable> value,
                        OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter)
                        throws IOException {
        	
        	ExtendedBytesWritable new_value = new ExtendedBytesWritable(new byte[17]);	 
           while(value.hasNext()){  
        	   new_value.set(value.next().getBytes(), 0, 0, new_value.getLength());
               output.collect(key, new BytesWritable(new_value.getBytes()));  
           }
//           output.collect(key, new BytesWritable(sum));                   
        }
    }
  
    /*******************************************
				Job Configuration
     *******************************************/
    
	private JobConf getCountUpJobConf(String jobName, Path inFilePath, Path outFilePath){
		
	    Path Output = new Path(jobName);			
		JobConf conf = new JobConf(ExampleProgram.class);
        conf.setJobName(jobName);     
       
        conf.setOutputKeyClass(BytesWritable.class);
        conf.setOutputValueClass(BytesWritable.class);	       
        conf.setInputFormat(PcapInputFormat.class);  
//        conf.setOutputFormat(TextOutputFormat.class);         
        conf.setOutputFormat(BinaryOutputFormat.class);        
        conf.setMapperClass(Map_CountUp.class);
        conf.setCombinerClass(Reduce_CountUp.class);          
        conf.setReducerClass(Reduce_CountUp.class);    
        
        FileInputFormat.setInputPaths(conf, inFilePath);
        FileOutputFormat.setOutputPath(conf, Output);
        
        return conf;
	}
    
	private JobConf getSortJobConf(String jobName, Path inFilePath, Path outFilePath){
		
	    Path Output = new Path(jobName);			
		JobConf conf = new JobConf(ExampleProgram.class);
		
        conf.setJobName(jobName);     
		conf.setInt("io.file.buffer.size", 17);        
//		conf.setInt("io.file.buffer.size", conf.getInt("count_len", 1)+Pcap.LEN_VAL2);  
        conf.setOutputKeyClass(BytesWritable.class);
        conf.setOutputValueClass(BytesWritable.class);	       
        conf.setInputFormat(BinaryInputFormat.class);  
        conf.setOutputFormat(TextOutputFormat.class);         
//        conf.setOutputFormat(BinaryOutputFormat.class);        
        conf.setMapperClass(Map_CountSort.class);
//        conf.setCombinerClass(Reduce_CountSort.class);          
        conf.setReducerClass(Reduce_CountSort.class);    
        
        FileInputFormat.setInputPaths(conf, inFilePath);
        FileOutputFormat.setOutputPath(conf, Output);
        
        return conf;
	}	

    /**
     * 
     * @param inputDir
     * @param outputDir
     */
    public void startCount(Path inputDir, Path outputDir){// throws IOException {
        
	try {
		FileSystem fs = FileSystem.get(ExampleProgram.conf);
        JobConf countJobconf = getCountUpJobConf("CountUp", inputDir, outputDir);        
        ExampleProgram.conf.addResource("binConfiguration.xml");
        conf.setInt("count_pos", Pcap.POS_DIP);
        conf.setInt("count_len", 4);
        
        // delete any output that might exist from a previous run of this job
        if (fs.exists(FileOutputFormat.getOutputPath(countJobconf))) {
          fs.delete(FileOutputFormat.getOutputPath(countJobconf), true);
        }        
		JobClient.runJob(countJobconf);	
		
        Path countOutputDir = FileOutputFormat.getOutputPath(countJobconf);
        JobConf sortJobConf = getSortJobConf("CountSort", countOutputDir, outputDir);  
        
        // delete any output that might exist from a previous run of this job
        if (fs.exists(FileOutputFormat.getOutputPath(sortJobConf))) {
          fs.delete(FileOutputFormat.getOutputPath(sortJobConf), true);
        }
        JobClient.runJob(sortJobConf);		
		
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
  }

  /**
   * Set the Configuration used by this Program.
   * 
   * @param conf The new Configuration to use by this program.
   */
/*
    public void setConf(Configuration conf) {
    this.conf = conf; // this will usually only be set by unit test.
  }
  */

  /**
   * 
   * @return This program's JobConf.
   */
  /*  
  public Configuration getConf() {
    return conf;
  }
  */
}
