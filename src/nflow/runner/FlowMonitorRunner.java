package nflow.runner;

import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

import nflow.hadoop.flow.analyzer.FlowPrint;

public class FlowMonitorRunner extends TimerTask{
	
	FlowPrint fprinter;
	
	String flow_inpath = "/user/root/flow_koren";
	String flow_outpath = "flow_koren_out";
	Calendar cal;
	
	public FlowMonitorRunner(){		
		fprinter = new FlowPrint();
	}
	
	public FlowMonitorRunner(String flow_inpath){
		this();
		this.flow_inpath = flow_inpath;
	}
	
	public FlowMonitorRunner(String flow_inpath, String flow_outpath){
		this();
		this.flow_inpath = flow_inpath;
		this.flow_outpath = flow_outpath;
	}


	public void run(){		
		cal = Calendar.getInstance( );	
		cal.add(Calendar.MINUTE, -5);
		String ds = String.format("%1$tY-%1$tm-%1$td.%1$tH%1$tM", cal);
		String area = "koren";
		
		try {
			Thread.sleep(60000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // give 20secs to close captured file	
		
		String inpath = "nf-v05."+ ds;
		fprinter.startFlowPrint(flow_inpath +"/"+ inpath, flow_outpath +"/"+ inpath);	
		
	} 
	
	public static void main(String[] args){		

		String strInterval = "5";
		
		int interval = Integer.parseInt(strInterval) * 60000;
		Calendar cal = Calendar.getInstance( );	
		try {		
			while((Integer.parseInt(String.format("%1$tM", cal))%5) != 0){
					Thread.sleep(1);
					cal = Calendar.getInstance( );
			}			
		
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		Timer timer = new Timer("flow_monitor_timer");		
		FlowMonitorRunner fmon = new FlowMonitorRunner();	
		timer.scheduleAtFixedRate(fmon, cal.getTime(), interval);
	}
}
