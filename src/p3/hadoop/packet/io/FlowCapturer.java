package p3.hadoop.packet.io;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Calendar;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import p3.common.lib.BinaryUtils;

import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.UDPPacket;
//import jpcap.packet.CflowPacket;

public class FlowCapturer{
	
	String dstPath = null;	//destination path in hdfs
	String deviceName;
	int interval = 5*60000;
	String exportIp = null;
	String dstPort = null;
	
	NetworkInterface device;
	Configuration conf = null;
	FileSystem fs = null;
	OutputStream out = null;
	int sampLen = -1;
	byte[] pcapheader = new byte[16];
	static final int PHEADER_LEN = 66;
		
	JpcapCaptor captor;
	
	/**
	 * Packet Printer Class
	 * @author yhlee
	 *
	 */
	class PacketPrinter implements PacketReceiver {	
		JpcapWriter writer = null;				
		public PacketPrinter(JpcapWriter writer){
			this.writer = writer;
		}					
		public void receivePacket(Packet packet) {    
			writer.writePacket(packet);	
		}
	}	
	
	/**
	 * convert packet to string and printout
	 * @author user
	 *
	 */
	class HadoopPacketPrinter implements PacketReceiver {	
	
		public HadoopPacketPrinter() throws IOException{	
			printPcapFileHeader();
		}
		
		void printPcapFileHeader() throws IOException{
			int[] fheader = {0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00
					, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
					, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
			
			int i=0;			
			while(i<fheader.length){
				out.write(fheader[i]);
				i++;
			}
		}
		
		public void receivePacket(Packet packet) {    			
			try {
				UDPPacket udp =(UDPPacket)packet;
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.sec),4));
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.usec),4));
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.caplen),4));
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.len),4));
				out.write(packet.header);
				out.write(packet.data, 0, packet.caplen - packet.header.length);
			
			} catch (IOException e) {
				// TODO Auto-generated catch block
				if(out!= null)
					try {
						out.close();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				e.printStackTrace();
			}		
		}
	}	
	
	static NetworkInterface[] getNetworkInterfaces()
	{
		//Obtain the list of network interfaces
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		
		for (int i = 0; i < devices.length; i++) {  			
			System.out.println(i+": "+devices[i].name + "(" + devices[i].description+")");   
			System.out.println(" datalink: "+devices[i].datalink_name + "(" + devices[i].datalink_description+")");  
			System.out.print(" MAC address:");  
			
			for (byte b : devices[i].mac_address)    
				System.out.print(Integer.toHexString(b&0xff) + ":");  
			System.out.println();  			
			for (NetworkInterfaceAddress a : devices[i].addresses)    
				System.out.println(" address:"+a.address + " " + a.subnet + " "+ a.broadcast);
		}		
		return devices;
	}
	
	void setFlowFilter(String exportIp, String dstPort){
		String filter = null;
		
		try {	
			filter = "ip and udp ";
			if(dstPort != null)
				filter += " and udp dst port " + dstPort;
			
			captor.setFilter(filter, true);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}				
	}
	
	void init() throws IOException{
		conf = new Configuration();
//      conf.set("hadoop.job.ugi", "hadoop,supergroup");
//		fs.setOwner(new_inpath, "hadoop", "supergroup");
//		conf.addResource("hdfs-default.xml");
//		conf.addResource("hdfs-site.xml");
		
		NetworkInterface[] devices = getNetworkInterfaces();
		
		for(int i=0;i<devices.length; i++){
			if(devices[i].name.equals(deviceName)){
				this.device = devices[i];
				System.out.println("Device Name: "+deviceName);
			}
		}			
		captor = JpcapCaptor.openDevice(device, 65535, false, 20);	
		captor.setNonBlockingMode(false);
		
		setFlowFilter(exportIp, dstPort);
	}		
	
	public FlowCapturer(String deviceName) throws IOException{	
		
		this.deviceName = deviceName;
		this.dstPath = "flow_koren/";
		this.interval = 5*60000;
		this.exportIp = null;
		this.dstPort = "5001";
		
		init();
	}
	
	public FlowCapturer(String deviceName, String dstPath, int interval, String dstPort) throws IOException{	
		
		this.deviceName = deviceName;
		if(dstPath==null) this.dstPath = "flow_koren/";
		else this.dstPath = dstPath;
		if(interval<0) this.interval = 5*60000;
		else this.interval = interval;
		this.exportIp = null;
		if(dstPort==null) this.dstPort = "5001";
		else this.dstPort=dstPort;
		
		init();
	}
	
	/**
	 * constructor
	 * @param exportIp
	 * @param dstPort
	 * @param deviceName
	 * @param dstPath
	 * @param interval
	 * @throws IOException 
	 */
	public FlowCapturer(String exportIp, String dstPort, String deviceName, String dstPath, int interval) throws IOException{

		this.deviceName = deviceName;
		this.dstPath = dstPath;
		this.interval = interval;
		
		init();
	}
		
	private String getFilePath(){
		Calendar C = Calendar.getInstance( );		
		return String.format("nf-v05.%1$tY-%1$tm-%1$td.%1$tH%1$tM", C);
//		return String.format("%1$tY/%1$tY-%1$tm/%1$tY-%1$tm-%1$td/nf-v05.%1$tY-%1$tm-%1$td.%1$tH%1$tM", C);
	}	
			
	void close_pcap(){
		try {
			if(out!=null){		
				out.close();
				out = null;
				System.out.println("stop@@@@");	
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void start(){
		
		try {
	        conf.set("hadoop.job.ugi", "hadoop,hadoop");
			fs = FileSystem.get(conf);
			fs.setConf(this.conf);
			
			Path curPath = new Path(dstPath+"/" + getFilePath());
			out = fs.create(curPath);
			System.out.println("start@@@@"+curPath);
//			FsPermission writePerm = FsPermission.createImmutable((short)0777);
//			fs.setPermission(curPath, writePerm);
			//fs.setOwner(curPath, "hadoop", "supergroup");
			
			long prevTs = System.currentTimeMillis() - System.currentTimeMillis() % (5*60*1000);
			HadoopPacketPrinter hp = new HadoopPacketPrinter();
			while(true){
				
				captor.processPacket(-1, hp);					
				if(System.currentTimeMillis()-prevTs > interval){
					
					close_pcap();
					curPath = new Path(dstPath+"/" + getFilePath());
					out = fs.create(curPath);
					System.out.println("start@@@@"+curPath);
					hp = new HadoopPacketPrinter();
					prevTs = System.currentTimeMillis() - System.currentTimeMillis() % (5*60*1000);
				}
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally{
			close_pcap();
		}
	}
	
	public void startCapture() throws IOException{		
			
		System.out.println("NetFlow Capturer Runner Called.");
		Calendar C = Calendar.getInstance( );	
		
		while((Integer.parseInt(String.format("%1$tM", C))%5) != 0){
			try {
				Thread.sleep(1);
				C = Calendar.getInstance( );
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}		
		start();	
	}
}
