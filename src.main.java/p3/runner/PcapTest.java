package p3.runner;

import java.util.Calendar;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.mapred.JobConf;

import p3.hadoop.common.pcap.lib.PcapRec;
import p3.ip.analyzer.P3CoralProgram;

public class PcapTest {
	static final String INPATH = "pcap_in";
	static final String OUTPATH = "PcapTest_out";	
	
	static JobConf conf = new JobConf(P3CoralProgram.class);

	static String getFilterFromFile(String filename){		
		return null;
	}
	
	public static void main(String[] args) throws Exception{
		String filter = "";
		String srcFilename = new String();		
		String dstFilename= OUTPATH+"/";
		String filterFilename = null;
		String key = null;
		String sort_field = "nothing";
		int topN = 0;
		int period = 60;
		String[] end = null;
		long cap_start = 0;
		long cap_end = 0;

		boolean rtag = false; 
		char argtype = 0;
		
		conf.addResource("p3-default.xml");
		
		/* Argument Parsing */
		int i = 0;
		while(i<args.length){
			if(args[i].startsWith("-")){
				
				argtype = args[i].charAt(1);
				switch (argtype){
					
				case 'B': case 'b':					
					String[] begin = args[i].substring(2).trim().split("-");
					if(begin.length<3)
						begin = args[i].substring(2).trim().split("/");
					if (begin.length == 3) {
						Calendar cal = Calendar.getInstance( );
						cal.set(Integer.parseInt(begin[0]),
								Integer.parseInt(begin[1]),Integer.parseInt(begin[2]));
						cal.add(Calendar.MONTH, -1);
						cal.add(Calendar.DATE, -1);
						cap_start = Math.round(cal.getTimeInMillis()/1000);
					}
					break;
					
				case 'E': case 'e':
					end = args[i].substring(2).trim().split("-");
					if(end.length<3)
						end = args[i].substring(2).trim().split("/");
					if (end.length == 3) {
						Calendar cal = Calendar.getInstance( );
						cal.set(Integer.parseInt(end[0]),
								Integer.parseInt(end[1]),Integer.parseInt(end[2]));
						cal.add(Calendar.MONTH, -1);
						cal.add(Calendar.DATE, 1);
						cap_end = Math.round(cal.getTimeInMillis()/1000);
					}
					break;
					
				case 'R': case 'r':
					srcFilename += args[i].substring(2);
					rtag = true;
					break;		
					
				case 'D': case 'd':
					dstFilename += args[i].substring(2);
					break;			
					
				case 'P': case 'p':
					period = Integer.parseInt(args[i].substring(2).trim());
					conf.setInt("pcap.record.rate.interval", period);
					break;		
					
				case 'F': case 'f':
					filterFilename = args[i].substring(2);
					break;
					
				case 'K': case 'k':
					key = args[i].substring(2).trim();
					
					if(key.equals("srcIP")){
						conf.setInt("pcap.record.key.pos", PcapRec.POS_SIP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_IPADDR);
					}else if(key.equals("dstIP")){
						conf.setInt("pcap.record.key.pos", PcapRec.POS_DIP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_IPADDR);
					}else if(key.equals("srcPort")){	
						conf.setInt("pcap.record.key.pos", PcapRec.POS_SP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_PORT);
					}else if(key.equals("dstPort")){		
						conf.setInt("pcap.record.key.pos", PcapRec.POS_DP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_PORT);
					}else{
						conf.setInt("pcap.record.key.pos", PcapRec.POS_PT);			
						conf.setInt("pcap.record.key.len", PcapRec.LEN_PROTO);
					}
					
					break;
				case 'S': case 's': // soring
					sort_field = args[i].substring(2).trim();
					
					if(sort_field.equals("bc"))
						conf.setInt("pcap.record.sort.field", 1);
					else if(sort_field.equals("pc"))
						conf.setInt("pcap.record.sort.field", 2);
					else 
						conf.setInt("pcap.record.sort.field", 0);
					break;
					
				case 'N': case 'n': // topN
					topN = Integer.parseInt(args[i].substring(2).trim());
					break;
					
				default:
					filter += args[i].substring(1)+" ";
				break;
				}					
			}
			else{
				switch (argtype){
					
				case 'B': case 'b':					
					String[] begin = args[i].trim().split("-");
					if(begin.length<3)
						begin = args[i].trim().split("/");
					if (begin.length == 3) {
						Calendar cal = Calendar.getInstance( );
						cal.set(Integer.parseInt(begin[0]),
								Integer.parseInt(begin[1]),Integer.parseInt(begin[2]));
						cal.add(Calendar.MONTH, -1);
						cal.add(Calendar.DATE, -1);
						cap_start = Math.round(cal.getTimeInMillis()/1000);
					}
					break;
					
				case 'E': case 'e':
					end = args[i].trim().split("-");
					if(end.length<3)
						end = args[i].trim().split("/");
					if (end.length == 3) {
						Calendar cal = Calendar.getInstance( );
						cal.set(Integer.parseInt(end[0]),
								Integer.parseInt(end[1]),Integer.parseInt(end[2]));
						cal.add(Calendar.MONTH, -1);
						cal.add(Calendar.DATE, 1);
						cap_end = Math.round(cal.getTimeInMillis()/1000);
					}
					break;
					
				case 'R': case 'r':
					srcFilename += args[i];
					rtag = true;
					break;		
					
				case 'D': case 'd':
					dstFilename += args[i];
					break;			
					
				case 'P': case 'p':
					period = Integer.parseInt(args[i].trim());
					conf.setInt("pcap.record.rate.interval", period);
					break;		
					
				case 'F': case 'f':
					filterFilename = args[i];
					break;
					
				case 'K': case 'k':
					key = args[i].trim();
					
					if(key.equals("srcIP")){
						conf.setInt("pcap.record.key.pos", PcapRec.POS_SIP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_IPADDR);
					}else if(key.equals("dstIP")){
						conf.setInt("pcap.record.key.pos", PcapRec.POS_DIP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_IPADDR);
					}else if(key.equals("srcPort")){	
						conf.setInt("pcap.record.key.pos", PcapRec.POS_SP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_PORT);
					}else if(key.equals("dstPort")){		
						conf.setInt("pcap.record.key.pos", PcapRec.POS_DP);
						conf.setInt("pcap.record.key.len", PcapRec.LEN_PORT);
					}else{
						conf.setInt("pcap.record.key.pos", PcapRec.POS_PT);			
						conf.setInt("pcap.record.key.len", PcapRec.LEN_PROTO);
					}
					
					break;
				case 'S': case 's': // soring
					sort_field = args[i].trim();
					
					if(sort_field.equals("bc"))
						conf.setInt("pcap.record.sort.field", 1);
					else if(sort_field.equals("pc"))
						conf.setInt("pcap.record.sort.field", 2);
					else 
						conf.setInt("pcap.record.sort.field", 0);
					break;
					
				case 'N': case 'n': // topN
					topN = Integer.parseInt(args[i].trim());
					break;
					
				default:
					filter += args[i]+" ";
				break;
				}
			}
			i++;
		}
		conf.setInt("pcap.record.sort.topN", topN);
		if(cap_end == 0){
			cap_end = cap_start + 432000;
		}
		
		if(srcFilename==null) srcFilename = INPATH+"/";

		if(filterFilename!=null)
			filter = getFilterFromFile(filterFilename);
		if(rtag){
			Path inputPath = new Path(srcFilename);
			Path outputDir = new Path(dstFilename);

			P3CoralProgram hcoral = new P3CoralProgram(conf);			
			hcoral.startTest(inputPath, outputDir, cap_start, cap_end);
		}
	}
}