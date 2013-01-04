package p3.hadoop.mapreduce.lib.input;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;
import org.apache.hadoop.util.LineReader;
//import org.apache.commons.logging.LogFactory;
//import org.apache.commons.logging.Log;

/**
 * Treats keys as offset in file and value as line. 
 */
public class PcapVlenRecordReader extends RecordReader<LongWritable,BytesWritable>{
  private static final Log LOG = LogFactory.getLog(PcapVlenRecordReader.class.getName());

  private CompressionCodecFactory compressionCodecs = null;
  private long start;
  private long pos;
  private long end;
  private PcapLineReader in;
  int maxLineLength;
  private boolean fileheader_skip = true;
  private LongWritable key = null;
  private BytesWritable value = null;

 
   public void initialize(InputSplit genericSplit, TaskAttemptContext context) throws IOException {

	   	FileSplit split = (FileSplit) genericSplit;
	   	Configuration job = context.getConfiguration();
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
	    if(skipFileHeader && fileheader_skip){
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


    /**
     * Read raw bytes from a PcapFile.
     */
    public boolean nextKeyValue() throws IOException {
    	
        if (key == null) {
            key = new LongWritable();
        }
        
        key.set(pos);
        
        if(value == null){
        	value = new BytesWritable();
        }
        
        int newSize = 0;
        
        while (pos < end) {
//          key.set(pos);

          newSize = in.readLine(value, maxLineLength, Math.max((int)Math.min(Integer.MAX_VALUE, end-pos),
                  maxLineLength));
          if (newSize == 0) {
        	  pos = end;
        	  break;
          }

          pos += newSize;
          if (newSize < maxLineLength) break;
          
          // line too long. try again
          LOG.info("Skipped line of size " + newSize + " at pos " + 
                   (pos - newSize));
        }
        if (newSize == 0) {
          key = null;
          value = null;
          return false;
        } else {
          return true;
        }  	
    }

    /**
     * Get the progress within the split
     */
    public float getProgress() {
      if (start == end) {
        return 0.0f;
      } else {
        return Math.min(1.0f, (pos - start) / (float)(end - start));
      }
    }

    public synchronized void close() throws IOException {
      if (in != null) {
        in.close(); 
      }
    }


	@Override
	public LongWritable getCurrentKey() throws IOException,
			InterruptedException {
		// TODO Auto-generated method stub
		return key;
	}


	@Override
	public BytesWritable getCurrentValue() throws IOException,
			InterruptedException {
		// TODO Auto-generated method stub
		return value;
	}
}