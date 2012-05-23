package p3.runner;

import org.apache.hadoop.mapred.JobConf;

import p3.hadoop.common.packet.PcapRec;




public class ArgumentParser {
	
	static final String INPATH = "pcap_in";
	static final String OUTPATH = "count_out";	
	
	static JobConf conf = new JobConf();

	static String getFilterFromFile(String filename){		
		return null;
	}
	
	public static JobConf parse(String[] args) throws Exception{
		String filter = "";
		String srcFilename = new String();		
		String dstFilename= OUTPATH+"/";
		String filterFilename = null;
		String key = null;
		String sort_field = "nothing";
		int topN = 0;
		int period = 60;
		
		boolean rtag = false; 
		conf.addResource("/home/dnlab/hadoop-0.19.2/conf/binConfiguration.xml");
		
		int i = 0;
		while(i<args.length){
			if(args[i].startsWith("-")){
				
				switch (args[i].charAt(1)){
				
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
				filter += args[i]+" ";
			}
			i++;
		}
		
		conf.setInt("pcap.record.sort.topN", topN);
		
		if(srcFilename==null) srcFilename = INPATH+"/";		
		if(filterFilename!=null)
			filter = getFilterFromFile(filterFilename);

		return conf;
	}
}