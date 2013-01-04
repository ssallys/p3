package p3.hadoop.mapred;

import java.io.IOException;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.RecordWriter;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.util.*;


public class BinaryOutputFormat<K, V> extends FileOutputFormat<K, V> {

  /** 
   * Inner class used for appendRaw
   */
/*
  static protected class WritableValueBytes implements ValueBytes {
    private BytesWritable value;

    public WritableValueBytes() {
      this.value = null;
    }
    public WritableValueBytes(BytesWritable value) {
      this.value = value;
    }

    public void reset(BytesWritable value) {
      this.value = value;
    }

    public void writeUncompressedBytes(DataOutputStream outStream)
      throws IOException {
      outStream.write(value.getBytes(), 0, value.getLength());
    }

    public void writeCompressedBytes(DataOutputStream outStream)
      throws IllegalArgumentException, IOException {
      throw
        new UnsupportedOperationException("WritableValueBytes doesn't support " 
                                          + "RECORD compression"); 
    }
    public int getSize(){
      return value.getLength();
    }
  }
  */
  @Override 
  public RecordWriter<K, V> 
             getRecordWriter(FileSystem ignored, JobConf job,
                             String name, Progressable progress)
    throws IOException {
    // get the path of the temporary output file 
    Path file = FileOutputFormat.getTaskOutputPath(job, name);
    
    FileSystem fs = file.getFileSystem(job);

    final FSDataOutputStream fileOut = fs.create(file, progress);

    return new RecordWriter<K, V>() {
        
        public void write(Object key, Object value)
          throws IOException {
        	if(key instanceof BytesWritable){
        		BytesWritable bkey = (BytesWritable)key;
        		fileOut.write(bkey.getBytes(), 0, bkey.getLength());
        	}
        	if(value instanceof BytesWritable){
        		BytesWritable bvalue = (BytesWritable)value;
        		fileOut.write(bvalue.getBytes(), 0, bvalue.getLength());
        	}        	
        }

        public void close(Reporter reporter) throws IOException { 
        	fileOut.close();
        }
      };
  }

  @Override 
  public void checkOutputSpecs(FileSystem ignored, JobConf job) 
            throws IOException {
    super.checkOutputSpecs(ignored, job);
  }
}

