package p3.hadoop.packet.io;

import java.io.IOException;
import java.net.InetAddress;

import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;

public class PacketSender {

	static void send(NetworkInterface device) throws IOException{
		
		//open a network interface to send a packet to
		JpcapSender sender=JpcapSender.openDevice(device);
		
		//create a TCP packet with specified port numbers, flags, and other parameters
		TCPPacket p=new TCPPacket(12,34,56,78,false,false,false,false,true,true,true,true,10,10);
		
		//specify IPv4 header parameters
		p.setIPv4Parameter(0,false,false,false,0,false,false,false,0,1010101,100,IPPacket.IPPROTO_TCP,  InetAddress.getByName("www.microsoft.com"),InetAddress.getByName("www.google.com"));
		
		//set the data field of the packet
		p.data=("data").getBytes();
		
		//create an Ethernet packet (frame)
		EthernetPacket ether=new EthernetPacket();
		
		//set frame type as IP
		ether.frametype=EthernetPacket.ETHERTYPE_IP;
		
		//set source and destination MAC addresses
		ether.src_mac=new byte[]{(byte)0,(byte)1,(byte)2,(byte)3,(byte)4,(byte)5};
		ether.dst_mac=new byte[]{(byte)0,(byte)6,(byte)7,(byte)8,(byte)9,(byte)10};
		
		//set the datalink frame of the packet p as ether
		p.datalink=ether;
		
		//send the packet p
		sender.sendPacket(p);
		sender.close();
	}
}