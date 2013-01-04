package p3.hadoop.mapred;

import java.io.IOException;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileSplit;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.JobConfigurable;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;

public class PcapInputFormat extends FileInputFormat<LongWritable,BytesWritable>
implements JobConfigurable {

	  private CompressionCodecFactory compressionCodecs = null;
	  
	  public void configure(JobConf conf) {
	    compressionCodecs = new CompressionCodecFactory(conf);
	  }
	  
	  protected boolean isSplitable(FileSystem fs, Path file) {
	    return compressionCodecs.getCodec(file) == null;
	  }

	  public RecordReader<LongWritable,BytesWritable> getRecordReader(
	                                          InputSplit genericSplit, JobConf job,
	                                          Reporter reporter)
	    throws IOException {
	    
	    reporter.setStatus(genericSplit.toString());
	    return new PcapVlenRecordReader(job, (FileSplit) genericSplit);
	  }
}
