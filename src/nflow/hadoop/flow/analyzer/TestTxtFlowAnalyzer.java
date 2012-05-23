package nflow.hadoop.flow.analyzer;


import java.util.HashMap;

public class TestTxtFlowAnalyzer {

	HashMap<String, String> JobList;

	public static void delay_Time(int delayTime){
		long saveTime = System.currentTimeMillis();
		long currTime = 0;
		while(currTime - saveTime < delayTime){
			currTime=System.currentTimeMillis();
		}
	}
	
	public static void start_threads(String sJobName, String srcDir){
		if(sJobName.equals("All")){
			
			thread_FlowAnalyzer byteperdport = 
				new thread_FlowAnalyzer("byteperDport", srcDir);
			thread_FlowAnalyzer packetperdport = 
				new thread_FlowAnalyzer("packetperDport", srcDir);
			thread_FlowAnalyzer bytepersport = 
				new thread_FlowAnalyzer("byteperSport", srcDir);
			thread_FlowAnalyzer packetpersport =
                                new thread_FlowAnalyzer("packetperSport", srcDir);
			thread_FlowAnalyzer byteperdip =
                                new thread_FlowAnalyzer("byteperDip", srcDir);
			thread_FlowAnalyzer bytepersip =
                                new thread_FlowAnalyzer("byteperSip", srcDir);
			thread_FlowAnalyzer packetperdip =
                                new thread_FlowAnalyzer("packetperDip", srcDir);
			thread_FlowAnalyzer packetpersip =
                                new thread_FlowAnalyzer("packetperSip", srcDir);
			
			byteperdport.start();
			delay_Time(10000);

			packetperdport.start();
			delay_Time(10000);
			
			bytepersport.start();
			delay_Time(10000);
			
			packetpersport.start();
			delay_Time(10000);

			byteperdip.start();
			delay_Time(10000);

			bytepersip.start();
			delay_Time(10000);

			packetperdip.start();
			delay_Time(10000);

			packetpersip.start();
			delay_Time(10000);
		} 
		else if(sJobName.equals("Two")){
			thread_FlowAnalyzer byteperdport = 
				new thread_FlowAnalyzer("byteperDport", srcDir);
			thread_FlowAnalyzer packetperdport = 
				new thread_FlowAnalyzer("packetperDport", srcDir);		
			
			byteperdport.start();
			delay_Time(10000);

			packetperdport.start();
		}
		else{
			thread_FlowAnalyzer t = new thread_FlowAnalyzer(sJobName, srcDir);
			t.start();			
		}
	}
	/**
	 * @param args
	 *
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		String sJobName = args[0];
		String srcDir = args[1];
		
		start_threads(sJobName, srcDir);
	}
}