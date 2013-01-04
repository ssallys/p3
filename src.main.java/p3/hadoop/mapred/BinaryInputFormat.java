package p3.hadoop.mapred;

import java.io.IOException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapred.FileSplit;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.JobConfigurable;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;

/**
 * InputFormat reading keys, values in binary (raw)
 * format.
 */
public class BinaryInputFormat
    extends BinaryFileInputFormat<BytesWritable,BytesWritable>
  	implements JobConfigurable {

  private CompressionCodecFactory compressionCodecs = null;
  
  public void configure(JobConf conf) {
    compressionCodecs = new CompressionCodecFactory(conf);
  }
  
  protected boolean isSplitable(FileSystem fs, Path file) {
    return compressionCodecs.getCodec(file) == null;
  }

  public RecordReader<BytesWritable,BytesWritable> getRecordReader(
      InputSplit split, JobConf job, Reporter reporter)
      throws IOException {
	  
	reporter.setStatus(split.toString());	  
    return new BinaryRecordReader(job, (FileSplit)split);
  }

  /**
   * Read records from a SequenceFile as binary (raw) bytes.
   */
  public static class BinaryRecordReader
      implements RecordReader<BytesWritable,BytesWritable> {
	 	  
//	private static final Log LOG
//	    = LogFactory.getLog(BinaryRecordReader.class.getName());
	
	private CompressionCodecFactory compressionCodecs = null;	  
	private long start;
	private long pos;
	private long end;
	private BinaryLineReader in;
	private int maxLineLength;

    public BinaryRecordReader(Configuration job, FileSplit split)
        throws IOException {

        this.maxLineLength = job.getInt("mapred.linerecordreader.maxlength", Integer.MAX_VALUE);    
        
        start = split.getStart();
		end = start + split.getLength();
		final Path file = split.getPath();
        
	    compressionCodecs = new CompressionCodecFactory(job);
	    final CompressionCodec codec = compressionCodecs.getCodec(file);		
		
		// open the file and seek to the start of the split
		FileSystem fs = file.getFileSystem(job);
		FSDataInputStream fileIn = fs.open(split.getPath());
     
	    if (codec != null) {
	        in = new BinaryLineReader(codec.createInputStream(fileIn), job);
	        end = Long.MAX_VALUE;
	    } else {
	        if (start != 0) { 	
	       		fileIn.seek(start);
	        }   
			in = new BinaryLineReader(fileIn, job);
	    }	        	
		this.pos = start;	
    }

    public BytesWritable createKey() {
      return new BytesWritable();
    }

    public BytesWritable createValue() {
      return new BytesWritable();
    }

    /**
     * Read raw bytes from a BinaryFile.
     */
    public synchronized boolean next(BytesWritable key, BytesWritable value)
        throws IOException {

        while (pos < end) {
//          key.set(pos);
        
          int newSize = in.readLine(value, maxLineLength,  Math.max((int)Math.min(Integer.MAX_VALUE, end-pos), 34));
          if (newSize == 0) return false;
          pos += newSize;
          if (newSize < maxLineLength) return true;
        }

        return false;    	
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
    
    public  synchronized long getPos() throws IOException {
      return pos;
    }

    public synchronized void close() throws IOException {
      if (in != null) {
        in.close(); 
      }
    }
  }
}
