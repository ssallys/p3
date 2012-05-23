package nflow.hadoop.flow.analyzer;


import java.util.HashMap;

public class TestCompressedFlow {

	public static void delay_Time(int delayTime){
		long saveTime = System.currentTimeMillis();
		long currTime = 0;
		while(currTime - saveTime < delayTime){
			currTime=System.currentTimeMillis();
		}
	}
	
	public static void start_threads(String sJobName, String srcDir){
		if(sJobName.equals("All")){
			
			Thread_CompressedFlowAnalyzer byteperdport = 
				new Thread_CompressedFlowAnalyzer("byteperDport", srcDir);
			Thread_CompressedFlowAnalyzer packetperdport = 
				new Thread_CompressedFlowAnalyzer("packetperDport", srcDir);
			Thread_CompressedFlowAnalyzer bytepersport = 
				new Thread_CompressedFlowAnalyzer("byteperSport", srcDir);
			Thread_CompressedFlowAnalyzer packetpersport =
                                new Thread_CompressedFlowAnalyzer("packetperSport", srcDir);
			Thread_CompressedFlowAnalyzer byteperdip =
                                new Thread_CompressedFlowAnalyzer("byteperDip", srcDir);
			Thread_CompressedFlowAnalyzer bytepersip =
                                new Thread_CompressedFlowAnalyzer("byteperSip", srcDir);
			Thread_CompressedFlowAnalyzer packetperdip =
                                new Thread_CompressedFlowAnalyzer("packetperDip", srcDir);
			Thread_CompressedFlowAnalyzer packetpersip =
                                new Thread_CompressedFlowAnalyzer("packetperSip", srcDir);
			
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
		else{
			Thread_CompressedFlowAnalyzer t = new Thread_CompressedFlowAnalyzer(sJobName, srcDir);
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