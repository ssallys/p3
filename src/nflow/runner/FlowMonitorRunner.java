package nflow.runner;

import java.io.IOException;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

import p3.hive.jdbc.lib.HiveJdbcClient;

import nflow.hadoop.flow.analyzer.FlowStats;
import nflow.hadoop.flow.analyzer.FlowPrint;

public class FlowMonitorRunner extends TimerTask{
	
	FlowPrint fprinter;
	FlowStats fanalyzer;
	Calendar cal;
	
	String flow_inpath = "/user/root/flow_koren";
	String flow_outpath = "flow_koren_out";
	String flowstats_outpath = "flowStats_out";
	int	interval = 5 * 60000;
	
	public FlowMonitorRunner(String flow_inpath, String flow_outpath, String flowstats_outpath, int interval) {
		super();
		this.flow_inpath = flow_inpath;
		this.flow_outpath = flow_outpath;
		this.flowstats_outpath = flowstats_outpath;
		this.interval = interval;
		
		fprinter = new FlowPrint();
		fanalyzer = new FlowStats();
	}

	public FlowMonitorRunner(){		
		fprinter = new FlowPrint();
		fanalyzer = new FlowStats();
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
		HiveJdbcClient hclient = new HiveJdbcClient();
		
		try {
			Thread.sleep(10000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // give 20secs to close captured file	
		
		System.out.println("");
		System.out.println("******************** START *********************");
		String inpath = "nf-v05."+ ds;
		int reduces = 1; 
		
		try {
			fprinter.startFlowPrint(flow_inpath +"/"+ inpath, flow_outpath +"/"+ inpath, reduces);	
			hclient.loadTableData("daily_flows", flow_outpath +"/"+ inpath, area, ds.substring(0,ds.indexOf(".")), ds.substring(ds.indexOf(".")+1));
	
			fanalyzer.startStats(flow_inpath +"/"+ inpath, flowstats_outpath +"/"+ inpath, reduces);	
			hclient.loadTableData("flowstats", flowstats_outpath +"/"+ inpath, area, ds.substring(0,ds.indexOf(".")), ds.substring(ds.indexOf(".")+1));	
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	} 
	
	public void startMonitor() throws InterruptedException{		
		
		Calendar cal = Calendar.getInstance( );	
		
		while((Integer.parseInt(String.format("%1$tM", cal))%5) != 0){
				Thread.sleep(1);
				cal = Calendar.getInstance( );
		}			
			
		Timer timer = new Timer("flow_monitor_timer");		
		timer.scheduleAtFixedRate(new FlowMonitorRunner(flow_inpath, flow_outpath, flowstats_outpath, interval), cal.getTime(), interval);
	}
	
	public static void main(String[] args) throws InterruptedException{		
		new FlowMonitorRunner().startMonitor();
	}
}
