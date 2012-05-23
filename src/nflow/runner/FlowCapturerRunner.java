package nflow.runner;

import java.io.IOException;
import java.util.Calendar;
import java.util.Timer;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import p3.hadoop.packet.io.CFlowPacketCapturerTimerTask;

public class FlowCapturerRunner {
	static String ExportIP, DstPort, DeviceName ,DstPath;			

	public static void main(String[] args) throws IOException{		
/*	
		ExportIP = args[0];
		DstPort = args[1];
		DeviceName = args[2];		
		DstPath = args[3];	
		String strInterval = args[4];
*/		
		System.out.println("NetFlow Capturer Runner Called.");
		ExportIP = null;//"168.188.3.23";
		DstPort = "5001";
		DeviceName = args[0];		
//		DstPath = "flow_cnu/";	
		DstPath = "flow_koren/";
		String strInterval = "5";
		
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
					
		Timer timer = new Timer("pcap");		
		CFlowPacketCapturerTimerTask pcap = new CFlowPacketCapturerTimerTask(ExportIP, DstPort, DeviceName, DstPath, interval);	
		timer.scheduleAtFixedRate(pcap, C.getTime(), interval);
	}
}
