package p3.runner;

import p3.hadoop.packet.io.PacketCapturer;

public class RunPcapH {
	static final String INPATH = "pcap_in";
	static final String OUTPATH = "pcap_out";	
	
/*	
	public static class PcapMapper extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, LongWritable, BytesWritable>{

		public void map
				(LongWritable key, BytesWritable value, 
				OutputCollector<LongWritable, BytesWritable> output, Reporter reporter) throws IOException {				
			output.collect(key,value);
		}
	}
   
	static void runJobFromFile(String filter, String inFileName, String outFileName) throws Exception {
		Path inputPath = new Path(inFileName);
		Path outputDir = new Path(outFileName);
		HCoralProgram hcoral = new HCoralProgram();
		hcoral.start(inputPath, outputDir);
	}
	
	static void runCaptureToFile(String devName, String filter, String srcFilename, String dstFilename, int sampLen){		
		PacketCapturer pcap = new PacketCapturer();
		pcap.startCapture(devName, filter, srcFilename, dstFilename, sampLen);
	}	*/
	
	static String getFilterFromFile(String filename){	
		return null;
	}
	
	public static void main(String[] args) throws Exception{
		String filter = "";
		String devName = null;
		String dstFilename = INPATH+"/";
		String srcFilename = null;
		String filterFilename = null;
		int sampLength = -1;
		
//		boolean rtag = false; 
		boolean wtag = false;
		
		int i = 0;
		while(i<args.length){
			if(args[i].startsWith("-")){
				switch (args[i].charAt(1)){
				case 'F': case 'f':
					filterFilename = args[i].substring(2);
					break;
				case 'R': case 'r':
					srcFilename = args[i].substring(2);
//					rtag = true;
					break;
				case 'W': case 'w':
					dstFilename += args[i].substring(2);
					wtag = true;
					break;
				case 'I': case 'i':
					devName = args[i].substring(2);
					break;
				case 'S': case 's':
					sampLength = Integer.parseInt(args[i].substring(2));
					break;
				default:
					filter += args[i].substring(1)+" ";
				break;
				}
					
			}
			else{
				filter += args[i]+" ";
			}
			i++;
		}
		
//		System.out.println("filter->"+filter);		
		if(sampLength<0) sampLength=90;

		if(filterFilename!=null)
			filter = getFilterFromFile(filterFilename);

//		runJobFromFile(filter, srcFilename, dstFilename);
		if(wtag){
			PacketCapturer pcap = new PacketCapturer();
			pcap.startCapture(devName, null, srcFilename, dstFilename, sampLength);
		}
	}
}