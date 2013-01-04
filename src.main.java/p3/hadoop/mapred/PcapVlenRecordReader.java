package p3.hadoop.mapred;

import java.io.IOException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapred.FileSplit;
import org.apache.hadoop.mapred.RecordReader;

/**
 * Treats keys as offset in file and value as line. 
 */
public class PcapVlenRecordReader implements RecordReader<LongWritable,BytesWritable> {
//  private static final Log LOG = LogFactory.getLog(LineRecordReader.class.getName());

  private CompressionCodecFactory compressionCodecs = null;
  private long start;
  private long pos;
  private long end;
  private PcapLineReader in;
  int maxLineLength;
  private boolean fileheader_skip = true;

 
   public PcapVlenRecordReader(Configuration job, FileSplit split)
        throws IOException {

	    this.maxLineLength = job.getInt("mapred.linerecordreader.maxlength",Integer.MAX_VALUE);
	    this.fileheader_skip = job.getBoolean("pcap.file.header.skip",true);
	    
	    start = split.getStart();
		end = start + split.getLength();
		final Path file = split.getPath();
		
	    compressionCodecs = new CompressionCodecFactory(job);
	    final CompressionCodec codec = compressionCodecs.getCodec(file);	
		
		// open the file and seek to the start of the split
		FileSystem fs = file.getFileSystem(job);
		FSDataInputStream fileIn = fs.open(split.getPath());

	    boolean skipFileHeader = false;
	    boolean skipPartialRecord = false;	
	    int fraction = 4000;
	    
	    if (codec != null) {
	      in = new PcapLineReader(codec.createInputStream(fileIn), job);
	      end = Long.MAX_VALUE;	      
	      skipFileHeader = true;	
	      
	    } else {
	      if (start == 0) {
	    	  skipFileHeader = true;
	      }else{
	    	  skipPartialRecord = true;
	    	  fileIn.seek(start);
	      }

	      in = new PcapLineReader(fileIn, job);
	    }
	    if(skipFileHeader){
			start += in.readFileHeader(); 	
	    }
	    if(skipPartialRecord){
	    	int skip = in.skipPartialRecord(fraction);
	    	while(skip == fraction){
	    		start+=skip;
	    		skip = in.skipPartialRecord(fraction);
	    	}
	    	start += skip; //in.skipPartialRecord(fraction);
	    	fileIn.seek(start); //move the position original + partial 
		    in = new PcapLineReader(fileIn, job);
/*		    
//	    	int skip = in.skipPartialRecord(fraction);
	    	start += in.skipPartialRecord(fraction);
	    	fileIn.seek(start); //move the position original + partial 
		    in = new PcapLineReader(fileIn, job);
*/
	    }
	    this.pos = start;
    }

	@Override
    public LongWritable createKey() {
      return new LongWritable();
    }

	@Override
    public BytesWritable createValue() {
      return new BytesWritable();
    }

    /**
     * Read raw bytes from a PcapFile.
     */
	@Override
    public synchronized boolean next(LongWritable key, BytesWritable value)
        throws IOException {

        while (pos < end) {
          key.set(pos);

          int newSize = in.readLine(value, maxLineLength, Math.max((int)Math.min(Integer.MAX_VALUE, end-pos),
                  maxLineLength));
          if (newSize == 0) {
        	  pos = end;
        	  return false;
          }

          pos += newSize;
          if (newSize < maxLineLength) return true;
        }
        return false;    	
    }

    /**
     * Get the progress within the split
     */
	  @Override
    public float getProgress() {
      if (start == end) {
        return 0.0f;
      } else {
        return Math.min(1.0f, (pos - start) / (float)(end - start));
      }
    }
	  @Override
    public  synchronized long getPos() throws IOException {
      return pos;
    }
	  @Override
    public synchronized void close() throws IOException {
      if (in != null) {
        in.close(); 
      }
    }
}