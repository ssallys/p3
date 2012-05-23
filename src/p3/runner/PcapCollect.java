package p3.runner;

import p3.hadoop.packet.io.PacketCapturer;

public class PcapCollect {
	static final String INPATH = "pcap_in";
	static final String OUTPATH = "pcap_out";	

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
		if(sampLength<0) sampLength=90;

		if(filterFilename!=null)
			filter = getFilterFromFile(filterFilename);

		if(wtag){
			PacketCapturer pcap = new PacketCapturer();
			pcap.startCapture(devName, filter, srcFilename, dstFilename, sampLength);
		}
	}
}