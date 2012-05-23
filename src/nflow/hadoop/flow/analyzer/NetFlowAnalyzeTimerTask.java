package nflow.hadoop.flow.analyzer;



import java.io.IOException;
import java.util.Calendar;
import java.util.TimerTask;
import java.lang.Thread;

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
import org.apache.hadoop.fs.*;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.TextOutputFormat;

import p3.hadoop.mapred.BinaryInputFormat;
import p3.hadoop.mapred.BinaryOutputFormat;

public class NetFlowAnalyzeTimerTask extends TimerTask{
	
	private static int DEFAULT_RECORD_SIZE = 48;
	private String inPath;
	private String date_year;
	private String date_month;
	private String date_day;
	private String date_HM;
	private String dst_path;
	
	public NetFlowAnalyzeTimerTask(String inPath, int record_size){
		this.inPath = inPath;
		DEFAULT_RECORD_SIZE = record_size;		
	}
	
	private JobConf getConf(String jobName, String inFilePath){
		
		String outPath = inFilePath.substring(inFilePath.lastIndexOf('/'));
		dst_path = outPath;
			
		JobConf conf = new JobConf(NetFlowAnalyzerwithNoTimerTask.class);
		conf.setInt("io.file.buffer.size", DEFAULT_RECORD_SIZE);	
        conf.setJobName(jobName);
        
        conf.setInputFormat(BinaryInputFormat.class);      
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
	//edit by wckang 2010.04.29	
	private void checkThread(Thread[] thd){
		int num_thread = 10;
		int [] thread_status = new int[num_thread];
		for(int i = 0; i < num_thread; i++){
			thread_status[i] = 0;
		}
		boolean check = true;
		while(check){
			for(int i = 0; i < num_thread; i++) {
				if(!thd[i].isAlive()) {
					thread_status[i] = 1;
				}
			}
			for(int i = 0; i < num_thread; i++){
				if(thread_status[i] == 0){
					break;
				}
				if((thread_status[i] == 1) && (i == (num_thread - 1))){
					check = false;
					break;
				}
			}
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

		checkThread(thd);

		resultDataCopy("SIP_IN");
		resultDataCopy("SIP_OUT");
		resultDataCopy("DIP_IN");
		resultDataCopy("DIP_OUT");
		resultDataCopy("SP_IN");
		resultDataCopy("SP_OUT");
		resultDataCopy("DP_IN");
		resultDataCopy("DP_OUT");
		resultDataCopy("SN_IN");
		resultDataCopy("SN_OUT");

	}
	
	private String getFilePath(){
		Calendar C = Calendar.getInstance( );	
		C.add(Calendar.MINUTE, -6);
		date_year = String.format("%1$tY", C);
		date_month = String.format("%1$tm", C);
		date_day = String.format("%1$td", C);
		date_HM = String.format("%1$tH%1$tM", C);

		return inPath + String.format("/%1$tY/%1$tY-%1$tm/%1$tY-%1$tm-%1$td/nf-v05.%1$tY-%1$tm-%1$td.%1$tH%1$tM", C);
	}

	private void resultDataCopy(String type){
		copyResult(getResultSourcePath(type), getResultFilePath(type));		
	}
	
	private void copyResult(String input, String output){
		int bytesRead;
		byte [] buffer = new byte[1024];
		
        Configuration conf = new Configuration();
		conf.addResource(new Path("/hadoop/conf/core-site.xml"));
		conf.addResource(new Path("/hadoop/conf/hdfs-site.xml"));
		conf.addResource(new Path("/hadoop/conf/mapred-site.xml"));
		conf.set("hadoop.job.ugi","root,root");
		try{
			FileSystem fs = FileSystem.get(conf);
	                Path inputFile = new Path(input);
        	        Path outputFile = new Path(output);

			FSDataInputStream in = fs.open(inputFile);
	                FSDataOutputStream out = fs.create(outputFile);

			while((bytesRead = in.read(buffer)) > 0){
				out.write(buffer, 0, bytesRead);
			}
			in.close();
			out.close();
			fs.close();
		} catch (IOException e){
        }
	}

	private String getResultFilePath(String type){
		String out_path = "/user/root/netflow_data_result";
		return out_path + "/" + date_year 
				+ "/" + date_year + "-" + date_month 
				+ "/" + date_year + "-" + date_month + "-" + date_day
				+ "/" + type
				+ "/" + date_year + "-" + date_month + "-" + date_day + "." + date_HM;
	}
	
	private String getResultSourcePath(String type){
		String out_path = "netResult/"+dst_path+"/"+type+"/part-00000";
		return out_path;
	}
	//edit end by wckang 2010.04.29
	public void run() {
		// TODO Auto-generated method stub
		String inFilePath = null;
		FileSystem fs = null;
		
		inFilePath = getFilePath();

		try {
			fs = FileSystem.get(new Configuration());
			
			System.out.println("fileName : "+inFilePath);		
			if(fs.isFile(new Path(inFilePath)))	startThread(inFilePath);
			else{
				Thread.sleep(1000);
				if(fs.isFile(new Path(inFilePath)))	startThread(inFilePath);
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
