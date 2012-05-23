package nflow.hadoop.flow.analyzer;


import java.io.IOException;

import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.DIP_Map_In;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.DIP_Map_Out;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.DP_Map_In;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.DP_Map_Out;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.Reduce3;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.SIP_Map_In;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.SIP_Map_Out;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.SP_Map_In;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.SP_Map_Out;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.Subnet_Map_In;
import nflow.hadoop.flow.analyzer.NetFlowAnalyzerwithNoTimerTask.Subnet_Map_Out;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobConf;

import p3.hadoop.mapred.BinaryInputFormat;
import p3.hadoop.mapred.BinaryOutputFormat;

public class NetFlowAnalyzerwithNoTimerTaskRunner{
	
	private static int DEFAULT_RECORD_SIZE = 48;
	private String inPath;	
	
	public NetFlowAnalyzerwithNoTimerTaskRunner(String inPath, int record_size){
		this.inPath = inPath;
		DEFAULT_RECORD_SIZE = record_size;
	}
	
	private JobConf getConf(String jobName, String inFilePath){
		
		String outPath = inFilePath.substring(inFilePath.lastIndexOf('/'));
			
		JobConf conf = new JobConf(NetFlowAnalyzerwithNoTimerTask.class);
		conf.setInt("io.file.buffer.size", DEFAULT_RECORD_SIZE);	
        conf.setJobName(jobName);
        
        conf.setInputFormat(BinaryInputFormat.class);      
//        conf.setOutputFormat(TextOutputFormat.class); 
        conf.setOutputFormat(BinaryOutputFormat.class);
        
        conf.setOutputKeyClass(BytesWritable.class);
        conf.setOutputValueClass(BytesWritable.class);	
        
        conf.setCombinerClass(Reduce3.class);
        conf.setReducerClass(Reduce3.class);    
        
        FileInputFormat.setInputPaths(conf, new Path(inFilePath));
        FileOutputFormat.setOutputPath(conf, new Path("netResult/"+outPath+"/"+jobName));
        
        return conf;
	}
	
	public static void delay_Time(int delayTime){
		long saveTime = System.currentTimeMillis();
		long currTime = 0;
		while(currTime - saveTime < delayTime){
			currTime=System.currentTimeMillis();
		}
	}
	
	private void startThread(String inFilePath){
		String jobName[] = {"SIP_IN","DIP_IN","SP_IN","DP_IN","SN_IN","SIP_OUT","DIP_OUT","SP_OUT","DP_OUT","SN_OUT"};
		Class mapper[] = {SIP_Map_In.class, DIP_Map_In.class, SP_Map_In.class, DP_Map_In.class,
					Subnet_Map_In.class, SIP_Map_Out.class, DIP_Map_Out.class, SP_Map_Out.class,
			 		DP_Map_Out.class, Subnet_Map_Out.class};
	
		JobConf[] conf = new JobConf[10];
		NetFlowAnalyzerwithNoTimerTask [] threadNetFlow = new NetFlowAnalyzerwithNoTimerTask[10];
		Thread thd[] = new Thread[10];
		
		for(int i=0;i<jobName.length; i++){
			conf[i] = getConf(jobName[i], inFilePath);
		    conf[i].setMapperClass(mapper[i]);			
			threadNetFlow[i] = new NetFlowAnalyzerwithNoTimerTask(conf[i]);		
			thd[i] = new Thread(threadNetFlow[i]);
			thd[i].start();	
			delay_Time(10000);
		}		
	}
	
	private void startThread(String inFilePath, String job){
		String jobName[] = {"SIP_IN","DIP_IN","SP_IN","DP_IN","SN_IN","SIP_OUT","DIP_OUT","SP_OUT","DP_OUT","SN_OUT"};
		Class mapper[] = {SIP_Map_In.class, DIP_Map_In.class, SP_Map_In.class, DP_Map_In.class,
					Subnet_Map_In.class, SIP_Map_Out.class, DIP_Map_Out.class, SP_Map_Out.class,
			 		DP_Map_Out.class, Subnet_Map_Out.class};
	
		JobConf conf = new JobConf();
		NetFlowAnalyzerwithNoTimerTask threadNetFlow;
		Thread thd = null;
		
		for(int i=0;i<jobName.length; i++){
			if(job.equals(jobName[i])){
				conf = getConf(jobName[i], inFilePath);
			    conf.setMapperClass(mapper[i]);			
				threadNetFlow = new NetFlowAnalyzerwithNoTimerTask(conf);	
				thd = new Thread(threadNetFlow);
				thd.start();
				delay_Time(10000);
			}
		}		
	}
	
	/**
	 * Don't use Thread
	 * @param inFilePath
	 * @param job
	 */
	private void startProcess(String inFilePath){
		String jobName[] = {"SIP_IN","DIP_IN","SP_IN","DP_IN","SN_IN","SIP_OUT","DIP_OUT","SP_OUT","DP_OUT","SN_OUT"};
		Class mapper[] = {SIP_Map_In.class, DIP_Map_In.class, SP_Map_In.class, DP_Map_In.class,
					Subnet_Map_In.class, SIP_Map_Out.class, DIP_Map_Out.class, SP_Map_Out.class,
			 		DP_Map_Out.class, Subnet_Map_Out.class};
	
		JobConf conf = new JobConf();
		NetFlowAnalyzerwithNoTimerTask threadNetFlow;
		
		for(int i=0;i<jobName.length; i++){
			conf = getConf(jobName[i], inFilePath);
		    conf.setMapperClass(mapper[i]);			
			threadNetFlow = new NetFlowAnalyzerwithNoTimerTask(conf);	
			threadNetFlow.run();
		}		
	}

	/**
	 * Don't use Thread
	 * @param inFilePath
	 * @param job
	 */
	private void startProcess(String inFilePath, String job){
		String jobName[] = {"SIP_IN","DIP_IN","SP_IN","DP_IN","SN_IN","SIP_OUT","DIP_OUT","SP_OUT","DP_OUT","SN_OUT"};
		Class mapper[] = {SIP_Map_In.class, DIP_Map_In.class, SP_Map_In.class, DP_Map_In.class,
					Subnet_Map_In.class, SIP_Map_Out.class, DIP_Map_Out.class, SP_Map_Out.class,
			 		DP_Map_Out.class, Subnet_Map_Out.class};
	
		JobConf conf = new JobConf();
		NetFlowAnalyzerwithNoTimerTask threadNetFlow;
		
		for(int i=0;i<jobName.length; i++){
			if(job.equals(jobName[i])){
				conf = getConf(jobName[i], inFilePath);
			    conf.setMapperClass(mapper[i]);			
				threadNetFlow = new NetFlowAnalyzerwithNoTimerTask(conf);	
				threadNetFlow.run();
			}
		}		
	}
	
	public void analyze(String jobName, boolean isThread) {
		// TODO Auto-generated method stub 
		
		String inFilePath = null;
		FileSystem fs = null;		
		inFilePath = inPath;

		try {
			fs = FileSystem.get(new Configuration());
			
			System.out.println("fileName : "+inFilePath);		
			if(fs.isFile(new Path(inFilePath))){
				
				if(jobName.equals("All")){
					if(isThread) startThread(inFilePath);
					else startProcess(inFilePath);
				}else{
					if(isThread) startThread(inFilePath, jobName);
					else startProcess(inFilePath, jobName);					
				}	
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}	
	
	public static void main(String[] args){		
			
		boolean isThread = false;
		if(args[0].equals("-T")||args[0].equals("-t")) isThread = true;

		try {
			Thread.sleep(60000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		NetFlowAnalyzerwithNoTimerTaskRunner analyzer = new NetFlowAnalyzerwithNoTimerTaskRunner(args[2],DEFAULT_RECORD_SIZE);
		analyzer.analyze(args[1], isThread);
	}	
}
