package p3.hadoop.packet.io;


import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;

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

public class PacketCapturer{ // implements Runnable{
	
	NetworkInterface device;
	Configuration conf = null;
	FileSystem fs = null;

	int sampLen = -1;
	byte[] pcapheader = new byte[16];
	static final int PHEADER_LEN = 66;
	OutputStream out = null;
	
	JpcapCaptor captor;
	
	public PacketCapturer() {
		super();
		conf = new Configuration();
        conf.set("hadoop.job.ugi", "hadoop,hadoop");
	}
	
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
//				if(packet.caplen==0) return;
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.sec),4));
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.usec),4));
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.caplen),4));
				out.write(BinaryUtils.flip(BinaryUtils.uIntToBytes(packet.len),4));
				

System.out.println();
System.out.print("packet cap length->"+packet.caplen+"->");
byte[] caplen = BinaryUtils.flip(BinaryUtils.flip(BinaryUtils.IntToBytes(packet.caplen),4),4);
//byte[] caplen = BinaryUtils.IntToBytes(packet.caplen);
int i =0;
while(i<caplen.length){
	System.out.print(caplen[i++]);
}
System.out.print("->"+BinaryUtils.byteToInt(caplen));
System.out.print("packet length->"+packet.len);

				out.write(packet.header);
				out.write(packet.data,0,packet.caplen-packet.header.length);

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
	
	
	
	/**
	 * 
	 * @return
	 */
	static NetworkInterface[] getNetworkInterfaces()
	{
		//Obtain the list of network interfaces
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		
		//for each network interface
		for (int i = 0; i < devices.length; i++) {  
			System.out.println(i+": "+devices[i].name + "(" + devices[i].description+")");   
			System.out.println(" datalink: "+devices[i].datalink_name + "(" + devices[i].datalink_description+")");  
			System.out.print(" MAC address:");  
			
			for (byte b : devices[i].mac_address)    
				System.out.print(Integer.toHexString(b&0xff) + ":");  
			System.out.println();  
			
			//print out its IP address, subnet mask and broadcast address  
			for (NetworkInterfaceAddress a : devices[i].addresses)    
				System.out.println(" address:"+a.address + " " + a.subnet + " "+ a.broadcast);
		}		
		return devices;
	}
	
	/**
	 * 
	 * @param deviceName
	 * @return
	 */
	NetworkInterface getDevice(String deviceName){
		NetworkInterface[] devices = getNetworkInterfaces();
		
		if(deviceName==null) return devices[0];
		
		for(int i=0;i<devices.length; i++){
			if(devices[i].name.equals(deviceName))
				return devices[i];
		}
		return null;
	}
	
	
	void setFlowFilter(String dstPort){
		String filter = " ip and udp ";
		
		try {
			captor = JpcapCaptor.openDevice(device, 65535, false, 20);	
			captor.setNonBlockingMode(false);
	
			//set a filter to only capture TCP/IPv4 packets
			filter = " not udp dst port " + dstPort;			
			
			captor.setFilter(filter, true);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}				
	}

	/**
	 * 
	 * @param filter
	 * @param filename
	 */
	public void startCapture(String deviceName, int count, String filter, String srcFilename, String dstFilename, int sampLen){
        
		try {	
			
			fs = FileSystem.get(URI.create(dstFilename), conf);
			out = fs.create(new Path(dstFilename));
			HadoopPacketPrinter hp = new HadoopPacketPrinter();
	        
	//		this.sampLen = sampLen;
			if(sampLen<0) sampLen = 65535;
			
			/* get device */
			device = getDevice(deviceName);		
			
			if(srcFilename!=null){
				captor = JpcapCaptor.openFile(srcFilename);
				while(true){
				  Packet packet=captor.getPacket();  
				  //if some error occurred or EOF has reached, break the loop  
				  if(packet==null || packet==Packet.EOF) break;  
				  //otherwise, print out the packet  
				  System.out.println(packet);
				}
				return;
			}
			else{
				captor = JpcapCaptor.openDevice(device, sampLen, false, 20);	
			}
			
			if(filter!= null)
				captor.setFilter(filter, true);
			captor.setFilter(" ip and udp dst port 5001 ", true);			
//			setFlowFilter("5001");			

//			JpcapWriter writer = JpcapWriter.openDumpFile(captor, "my2.pcap");
//			captor.loopPacket(-1, new PacketPrinter(writer));	
			captor.loopPacket(count, hp);	
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
	
	public void startCapture(int count, String filter, String srcFilename, String dstFilename, int sampLen){
		startCapture(null, count, filter, srcFilename, dstFilename, sampLen);
	}
	
	/**
	 * 
	 * @param devName
	 * @param filter
	 * @param dstFilename
	 * @param sampLen
	 */
	public void startCapture(String devName, String filter, String srcFilename, String dstFilename, int sampLen){
		startCapture(devName, -1, filter, srcFilename, dstFilename, sampLen);
	}
	
	public void startCapture(String filter, String srcFilename, String dstFilename, int sampLen){
		startCapture(null, -1, filter, srcFilename, dstFilename, sampLen);
	}
	
	public void startCapture(String srcFilename, String dstFilename, int sampLen){
		startCapture(null, -1, null, srcFilename, dstFilename, sampLen);
	}
}
