package p3.hadoop.mapred;

import java.io.IOException;
import java.io.InputStream;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.BytesWritable;

public class BinaryLineReader {

  private static final int DEFAULT_BUFFER_SIZE = 29;
  private int bufferSize = DEFAULT_BUFFER_SIZE;
  private InputStream in;
  private byte[] buffer;
  // the number of bytes of real data in the buffer
  private int bufferLength = 0;
  private byte[] tmp_buffer;
  private int tmp_pos = 0;
  
  /**
   * Create a line reader that reads from the given stream using the 
   * given buffer-size.
   * @param in The input stream
   * @param bufferSize Size of the read buffer
   * @throws IOException
   */
  public BinaryLineReader(InputStream in, int bufferSize) {
    this.in = in;
    this.bufferSize = bufferSize;
    this.buffer = new byte[this.bufferSize];
    this.tmp_buffer = new byte[this.bufferSize];   
  }

  /**
   * Create a line reader that reads from the given stream using the
   * <code>io.file.buffer.size</code> specified in the given
   * <code>Configuration</code>.
   * @param in input stream
   * @param conf configuration
   * @throws IOException
   */
  public BinaryLineReader(InputStream in, Configuration conf) throws IOException {
	  this(in, conf.getInt("io.file.buffer.size", DEFAULT_BUFFER_SIZE));
  }

  /**
   * Close the underlying stream.
   * @throws IOException
   */
  public void close() throws IOException {
    in.close();
  }


  private boolean readPartialLine(int newBufferLen) throws IOException{
	  
		byte[] newbuffer = new byte[newBufferLen];       //bufferLength];			
		if((bufferLength = in.read(newbuffer))>0){
			System.arraycopy(newbuffer, 0, tmp_buffer, tmp_pos, bufferLength); 		
			tmp_pos+=bufferLength;		
			
			if(tmp_pos < bufferSize){
				readPartialLine(bufferSize-tmp_pos);
			}
		}		
		return true;
  }
  
  public int readLine(BytesWritable bytes, int maxLineLength,
                      int maxBytesToConsume) throws IOException {

	bytes.set(new BytesWritable());
	
	if((bufferLength = in.read(buffer))+tmp_pos < bufferSize){
		System.arraycopy(buffer, 0, tmp_buffer, tmp_pos, bufferLength); 
		tmp_pos+=bufferLength;
		
		if(tmp_pos < bufferSize){
			readPartialLine(bufferSize-tmp_pos);
		}
		bytes.set(tmp_buffer, 0, bufferSize);
		
	}else{
		bytes.set(buffer, 0, bufferSize);		
	}
	  	tmp_pos = 0;
	  	return bufferSize;
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
