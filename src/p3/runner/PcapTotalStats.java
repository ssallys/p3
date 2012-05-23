package p3.runner;

import java.io.InputStream;
import java.net.URI;
import java.util.Calendar;

import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.mapred.JobConf;

import p3.hadoop.common.packet.PcapRec;
import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.packet.analyzer.P3CoralProgram;

public class PcapTotalStats {
	static final String INPATH = "pcap_in";
	static final String OUTPATH = "PcapTotalStats_out";	
	private static final int PCAP_FILE_HEADER_LENGTH = 24;  
	private static final int ONEDAYINSEC = 432000;
	
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
		long cap_start = Long.MAX_VALUE;
		long cap_end = Long.MIN_VALUE;
		boolean fh_skip = true;

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
						cap_start = cal.getTimeInMillis()/1000;
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
					
				case 'H': case 'h':	// file header don't skip(in case of no pcap file header)
					fh_skip = false;
					conf.setBoolean("pcap.file.header.skip", fh_skip);
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
						cap_start = cal.getTimeInMillis()/1000;
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
		
		if(srcFilename==null) srcFilename = INPATH+"/";

		if(filterFilename!=null)
			filter = getFilterFromFile(filterFilename);
		if(rtag){
			
			/* get capture time automatically */
			Path inputPath = new Path(srcFilename);
			FileSystem fs = FileSystem.get(URI.create(srcFilename), conf);
			InputStream in = null;
		    byte[] buffer = new byte[PCAP_FILE_HEADER_LENGTH];
			Calendar cal = Calendar.getInstance();
			long timestamp = 0;
			
			if(cap_start == Long.MAX_VALUE){
				FileStatus stat = fs.getFileStatus(inputPath);
				if(stat.isDir()){
					FileStatus[] stats = fs.listStatus(inputPath);
					for(FileStatus curfs : stats){
						if(!curfs.isDir()){
							System.out.println(curfs.getPath());
							in = fs.open(curfs.getPath());
							if(fh_skip)
								in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
							in.read(buffer, 0, 4);
							timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
							if(timestamp < cap_start)
								cap_start = timestamp;
							if(timestamp > cap_end)
								cap_end = timestamp;
						}
					}
					in.close();
					fs.close();
					cap_end = cap_end + ONEDAYINSEC;
				}else{
					in = fs.open(inputPath);
					if(fh_skip)
						in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
					in.read(buffer, 0, 4);
					timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
					System.out.println(timestamp);
					cap_start = timestamp;
					
					if(cap_end == Long.MIN_VALUE){
						cap_end = cap_start+ONEDAYINSEC;
					}
					in.close();
					fs.close();
				}				
	/*
				cal.setTimeInMillis(timestamp*1000);
				System.out.println(String.format("%1$tY-%1$tm-%1$td", cal));	
				cal.add(Calendar.DATE, 1);
				System.out.println(String.format("%1$tY-%1$tm-%1$td", cal));
				System.out.println(cal.getTimeInMillis()/1000 - timestamp);
				return;*/
			}
			
			if(cap_end == Long.MIN_VALUE)
				cap_end = cap_start+ONEDAYINSEC;
			
//			Path inputPath = new Path(srcFilename);
			Path outputDir = new Path(dstFilename);

			P3CoralProgram hcoral = new P3CoralProgram(conf);
			hcoral.startStats(inputPath, outputDir, cap_start, cap_end, fh_skip);
		}
	}
}