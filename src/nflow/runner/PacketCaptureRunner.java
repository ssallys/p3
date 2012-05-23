package nflow.runner;

import java.util.Calendar;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import p3.hadoop.packet.io.PacketCapturer;

//import nflow.hadoop.flow.io.PacketCapturer;



public class PacketCaptureRunner {
	static String ExportIP, DstPort, DeviceName ,DstPath;		
	static ScheduledExecutorService executor;
	static PacketCapturer pcap;
	
	public static void execute(Runnable command) {
		  executor.execute(command);
	}

	public static void scheduleAtFixedRate(Runnable command, int start, int interval ){
	    executor.scheduleAtFixedRate(command, start, interval*2, TimeUnit.MILLISECONDS);
	}

	public static void main(String[] args){		
	
		ExportIP = args[0];
		DstPort = args[1];
		DeviceName = args[2];		
		DstPath = args[3];	
		String strInterval = args[4];
		int interval = Integer.parseInt(strInterval) * 60000;	
		
		Calendar C = Calendar.getInstance( );	
		while((Integer.parseInt(String.format("%1$tM", C))%5) != 0){
			try {
				Thread.sleep(1);
				C = Calendar.getInstance( );
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
/*		pcap = new PacketCapturer(ExportIP, DstPort, DeviceName, DstPath, interval);	
		executor = new ScheduledThreadPoolExecutor(2);				
	    scheduleAtFixedRate(pcap, 0, interval);
*/	    
	}
}