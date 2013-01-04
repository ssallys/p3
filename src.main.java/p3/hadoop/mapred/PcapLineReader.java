package p3.hadoop.mapred;


import java.io.IOException;
import java.io.InputStream;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.BytesWritable;

import p3.common.lib.BinaryUtils;
import p3.common.lib.Bytes;

public class PcapLineReader {

  private static final int DEFAULT_BUFFER_SIZE = 2048;
  private int bufferSize = DEFAULT_BUFFER_SIZE;
  private static final int PCAP_FILE_HEADER_LENGTH = 24;  
  private static final int PCAP_PACKET_HEADER_LENGTH = 16;
  private static final int PCAP_PACKET_HEADER_CAPLEN_POS=8;
  private static final int PCAP_PACKET_HEADER_WIREDLEN_POS=12;
  private static final int PCAP_PACKET_HEADER_CAPLEN_LEN=4;  
  private static final int PCAP_PACKET_HEADER_TIMESTAMP_LEN=4; 
  private static final int PCAP_PACKET_MIN_LEN=53; 
  private static final int PCAP_PACKET_MAX_LEN=1519; 
  private static final int MAGIC_NUMBER = 0xd4c3b2a1 ;
  private static final int MIN_PKT_SIZE = 42;  

  private long min_captime; 
  private long max_captime;
	
  private InputStream in;
  
  private byte[] buffer;
  byte[] pcap_header;
  private int bufferLength = 0;
  int consumed = 0;
  
  /**
   * Create a line reader that reads from the given stream using the 
   * given buffer-size.
   * @param in The input stream
   * @param bufferSize Size of the read buffer
   * @throws IOException
   */
  public PcapLineReader(InputStream in, int bufferSize, long min_captime, long max_captime) {
    this.in = in;
    this.bufferSize = bufferSize;
    this.buffer = new byte[this.bufferSize];
    this.min_captime = min_captime;
    this.max_captime = max_captime;
  }

  /**
   * Create a line reader that reads from the given stream using the
   * <code>io.file.buffer.size</code> specified in the given
   * <code>Configuration</code>.
   * @param in input stream
   * @param conf configuration
   * @throws IOException
   */
  public PcapLineReader(InputStream in, Configuration conf) throws IOException {
	  this(in, DEFAULT_BUFFER_SIZE //conf.getInt("io.file.buffer.size", DEFAULT_BUFFER_SIZE)
			 , conf.getLong("pcap.file.captime.min", 1309412600)
			 , conf.getLong("pcap.file.captime.max", conf.getLong("pcap.file.captime.max", 1309412600)+(86400*2)));
  }
 
  /**
   * Close the underlying stream.
   * @throws IOException
   */
  public void close() throws IOException {
    in.close();
  }
   
  /**
   * skip partial record
   * @return was there more data?
   * @throws IOException
   */
  int skipPartialRecord(int fraction) throws IOException {
	int pos = 0;
	byte[] captured = new byte[fraction];
	byte[] tmpTimestamp1 = new byte[PCAP_PACKET_HEADER_TIMESTAMP_LEN];
	byte[] tmpTimestamp2 = new byte[PCAP_PACKET_HEADER_TIMESTAMP_LEN];
	byte[] tmpCapturedLen1 = new byte[PCAP_PACKET_HEADER_CAPLEN_LEN];	
	byte[] tmpWiredLen1 = new byte[PCAP_PACKET_HEADER_CAPLEN_LEN];
	byte[] tmpCapturedLen2 = new byte[PCAP_PACKET_HEADER_CAPLEN_LEN];	
	byte[] tmpWiredLen2 = new byte[PCAP_PACKET_HEADER_CAPLEN_LEN];	
	int caplen1 = 0;
	int wiredlen1 = 0;	
	int caplen2 = 0;
	int wiredlen2 = 0;	
	long timestamp1, timestamp2=0;
//	int min_packet_size = 50;
	int size = 0;
	long endureTime = 100;
	
	if((size = in.read(captured)) < MIN_PKT_SIZE ) return 0;
//	return 100;
	
	while(pos<size){
		
		if(size-pos < (PCAP_PACKET_HEADER_LENGTH*2) || size-pos < PCAP_PACKET_MIN_LEN ){
			pos = size;
			break;
		}
		
		System.arraycopy(captured, pos, tmpTimestamp1, 0, PCAP_PACKET_HEADER_TIMESTAMP_LEN);
		timestamp1 = Bytes.toLong(BinaryUtils.flipBO(tmpTimestamp1,4)); 
		
		/* first header */
		System.arraycopy(captured, pos+PCAP_PACKET_HEADER_CAPLEN_POS, tmpCapturedLen1, 0, PCAP_PACKET_HEADER_CAPLEN_LEN);		
		caplen1 = Bytes.toInt(BinaryUtils.flipBO(tmpCapturedLen1,4)); 
		
		System.arraycopy(captured, pos+PCAP_PACKET_HEADER_WIREDLEN_POS, tmpWiredLen1, 0, PCAP_PACKET_HEADER_CAPLEN_LEN);		
		wiredlen1 = Bytes.toInt(BinaryUtils.flipBO(tmpWiredLen1,4)); 
		
		if(caplen1>PCAP_PACKET_MIN_LEN && caplen1<PCAP_PACKET_MAX_LEN &&  (size-pos-(PCAP_PACKET_HEADER_LENGTH*2)-caplen1)>0) {

			/* second header */
			System.arraycopy(captured, pos+PCAP_PACKET_HEADER_LENGTH+caplen1+PCAP_PACKET_HEADER_CAPLEN_POS, tmpCapturedLen2, 0, PCAP_PACKET_HEADER_CAPLEN_LEN);		
			caplen2 = Bytes.toInt(BinaryUtils.flipBO(tmpCapturedLen2,4)); 
			
			System.arraycopy(captured, pos+PCAP_PACKET_HEADER_LENGTH+caplen1+PCAP_PACKET_HEADER_WIREDLEN_POS, tmpWiredLen2, 0, PCAP_PACKET_HEADER_CAPLEN_LEN);		
			wiredlen2 = Bytes.toInt(BinaryUtils.flipBO(tmpWiredLen2,4)); 
			
			System.arraycopy(captured, pos+PCAP_PACKET_HEADER_LENGTH+caplen1, tmpTimestamp2, 0, PCAP_PACKET_HEADER_TIMESTAMP_LEN);			
			timestamp2 = Bytes.toLong(BinaryUtils.flipBO(tmpTimestamp2,4));

			if(timestamp1 >= min_captime && timestamp1 < max_captime && min_captime <= timestamp2 && timestamp2 < max_captime ){
				if(wiredlen1>PCAP_PACKET_MIN_LEN && wiredlen1<PCAP_PACKET_MAX_LEN && wiredlen2>PCAP_PACKET_MIN_LEN && wiredlen2<PCAP_PACKET_MAX_LEN){
					if(caplen1>0 && caplen1 <= wiredlen1 && caplen2>0 && caplen2 <= wiredlen2){
						if(timestamp2 >= timestamp1 && (timestamp2 - timestamp1)< endureTime)
								return pos;
					}
				}
			}
		}
		

		
		pos++;
	}	
    return pos;
  }
  
  /**
   * Fill the buffer with more data.
   * @return was there more data?
   * @throws IOException
   */
  int readPacket(int packetLen) throws IOException {
	  
	int bufferPosn = PCAP_PACKET_HEADER_LENGTH;	  
	byte[] tmp_buffer = new byte[packetLen];	  
	
    if((bufferLength = in.read(tmp_buffer))<packetLen){
        System.arraycopy(tmp_buffer, 0, buffer, bufferPosn, bufferLength);
        bufferPosn += bufferLength;
        
		byte[] newpacket = new byte[packetLen-bufferLength];
		
		if((bufferLength = in.read(newpacket))<0) return bufferPosn;
		System.arraycopy(newpacket, 0, buffer, bufferPosn, bufferLength);
		
		
    }else
        System.arraycopy(tmp_buffer, 0, buffer, bufferPosn, bufferLength);
    
    bufferPosn += bufferLength;
    
    return bufferPosn;
  }
  
  int readPacketHeader(){
	  
	int headerLength = 0;
	int headerPosn = 0;
	pcap_header = new byte[PCAP_PACKET_HEADER_LENGTH];

	  
	byte[] tmp_header = new byte[PCAP_PACKET_HEADER_LENGTH];
	BytesWritable capturedLen = new BytesWritable();
		
	try {
		if((headerLength = in.read(pcap_header))<PCAP_PACKET_HEADER_LENGTH){
			
			if(headerLength == -1)	return 0;			
			headerPosn+= headerLength;
			
			byte[] newheader = new byte[PCAP_PACKET_HEADER_LENGTH-headerLength];
			
			if((headerLength = in.read(newheader))<0){
				consumed = headerPosn; 
				return -1;
			}
			System.arraycopy(newheader, 0, pcap_header, headerPosn, headerLength);
		}
		capturedLen.set(pcap_header,PCAP_PACKET_HEADER_CAPLEN_POS, PCAP_PACKET_HEADER_CAPLEN_LEN);		
        System.arraycopy(pcap_header, 0, buffer, 0, PCAP_PACKET_HEADER_LENGTH);
		headerPosn=0;
		
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return Bytes.toInt(BinaryUtils.flipBO(capturedLen.getBytes(),4));
  }
  
  public int readFileHeader(){
	  try {
//		  bufferPosn = 0;
		  byte[] magic = new byte[4];
		  bufferLength = in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
		  System.arraycopy(buffer, 0, magic, 0, magic.length);
		  
		  // if there is no pcap file header, don't skip !!
		  if(Bytes.toInt(magic)!= MAGIC_NUMBER)
			  return 0;
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    return bufferLength;
  }
  
  /**
   * Read from the InputStream into the given Text.
   * @param str the object to store the given line
   * @param maxLineLength the maximum number of bytes to store into str.
   * @param maxBytesToConsume the maximum number of bytes to consume in this call.
   * @return the number of bytes read including the newline
   * @throws IOException if the underlying stream throws
   */
	public int readLine(BytesWritable bytes, int maxLineLength,
	          int maxBytesToConsume) throws IOException {
		
		bytes.set(new BytesWritable());
		boolean hitEndOfFile = false;
		long bytesConsumed = 0;

		int caplen = readPacketHeader();
		
		if(caplen==0)
			bytesConsumed = 0;
		else if (caplen==-1)
			bytesConsumed += consumed;
		else{
//			bytesConsumed += PCAP_PACKET_HEADER_LENGTH;
		
			if(caplen>0 && caplen<PCAP_PACKET_MAX_LEN){	
				if ((bufferLength = readPacket(caplen)) < caplen+PCAP_PACKET_HEADER_LENGTH) {
					hitEndOfFile = true;
				}
				bytesConsumed += bufferLength;
				
				if (!hitEndOfFile) {
					bytes.set(buffer, 0, caplen+PCAP_PACKET_HEADER_LENGTH);
				}	
			}
		}
		return (int)Math.min(bytesConsumed, (long)Integer.MAX_VALUE);	
	} 
  
	
  /**
   * Read from the InputStream into the given Text.
   * @param str the object to store the given line
   * @param maxLineLength the maximum number of bytes to store into str.
   * @return the number of bytes read including the newline
   * @throws IOException if the underlying stream throws
   */
  public int readLine(BytesWritable str, int maxLineLength) throws IOException {
    return readLine(str, maxLineLength, Integer.MAX_VALUE);
  }

  /**
   * Read from the InputStream into the given Text.
   * @param str the object to store the given line
   * @return the number of bytes read including the newline
   * @throws IOException if the underlying stream throws
   */
  public int readLine(BytesWritable str) throws IOException {
    return readLine(str, Integer.MAX_VALUE, Integer.MAX_VALUE);
  }

}
