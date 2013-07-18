package nflow.runner;

import java.io.IOException;
import java.util.Calendar;
import java.util.Timer;

import p3.hadoop.packet.io.FlowCapturer;

public class FlowCapturerRunner {
	static String ExportIP, DstPort, DeviceName ,DstPath;			

	public static void main(String[] args) throws IOException{		

		System.out.println("NetFlow Capturer Runner Called.");
		ExportIP = null;
		DstPort = "5000";
		DeviceName = "eth2";
		DstPath = "flow_cnu/";
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
		new FlowCapturer(ExportIP, DstPort, DeviceName, DstPath, interval).start();	
	}
}
