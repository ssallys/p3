package nflow.runner;

import nflow.hadoop.flow.analyzer.FlowDetect;
import nflow.hadoop.flow.analyzer.FlowDetect2;
import nflow.hadoop.flow.analyzer.FlowStats;
import nflow.hadoop.flow.analyzer.FlowPrint;

import org.apache.hadoop.fs.Path;

import p3.hadoop.packet.io.FlowCapturer;

public class Runner {
	static final String INPATH = "tstat_in";
	public static void main(String[] args) throws Exception{

		String inPathStr = new String();
		String asnPathName = new String();
		String devName = null;
		char job = 's';
		int fieldNo = 0;
		int k = 0;
		char argtype = 0;
		int reduces = 1;
		
		/* Argument Parsing */
		int i = 0;
		while(i<args.length){
			if(args[i].startsWith("-")){
				
				argtype = args[i].charAt(1);
				switch (argtype){		
				
				case 'I': case 'i':
					devName = args[i].substring(2);
					break;						
				case 'R': case 'r':
					inPathStr = args[i].substring(2);
					break;													
				case 'N': case 'n':
					reduces = Integer.parseInt(args[i].substring(2).trim());
					break;						
				case 'K': case 'k':
					k = Integer.parseInt(args[i].substring(2).trim());
					break;											
				case 'J': case 'j':
					job = args[i].substring(2).trim().charAt(0);
					break;	
				}					
			}
			i++;
		}
		
		FlowStats fanalyzer;
		boolean isreal = false;
		switch(job){	
				
			case 'c':
				System.out.println("FlowCapturer called.");
				new FlowCapturer(devName,"flow_cnu/", 5*60000, "5000").startCapture();
				break;				
			case 'm':
				System.out.println("FlowMonitor called.");
				String flow_inpath = "/user/root/flow_cnu";
				String flow_outpath = "flow_cnu_out";
				String flowstats_outpath = "flowStats_out";
				int interval = 5*60000;
				new FlowMonitorRunner(flow_inpath, flow_outpath, flowstats_outpath, interval).startMonitor();
				break;	
			case 'd':
				System.out.println("FlowDetector called.");
//				FlowDetect fd1 = new FlowDetect();
//				isreal = false;
//				fd1.startStats(inPathStr, reduces, isreal);	
				break;	
			case 'D':
				System.out.println("FlowDetector in AIO called.");
//				FlowDetect2 fd2 = new FlowDetect2();
//				isreal = true;
//				fd2.startStats(inPathStr, reduces, isreal);
				break;	
			case 'r':
				System.out.println("FlowDetector in realtime called.");
				FlowDetect fd = new FlowDetect();
				isreal = true;
				fd.startStats(inPathStr, reduces, isreal);
				break;	
			case 's':
				System.out.println("FlowAnalyzer called.");
				isreal = false;
				fanalyzer = new FlowStats();
				fanalyzer.startStats(inPathStr, reduces, isreal);	
				break;			
			case 'S':
				System.out.println("FlowAnalyzer in realtime called.");
				isreal = true;
				fanalyzer = new FlowStats();
				fanalyzer.startStats(inPathStr, reduces, isreal);	
				break;		
			case 'p':
				System.out.println("FlowPrint called.");
				FlowPrint fprinter = new FlowPrint();
				fprinter.startFlowPrint(inPathStr, reduces);
				break;	
		}
	}
}