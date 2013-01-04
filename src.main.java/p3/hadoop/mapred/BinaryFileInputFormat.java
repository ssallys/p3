package p3.hadoop.mapred;

import java.io.IOException;
import java.util.ArrayList;

import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.PathFilter;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileSplit;
import org.apache.hadoop.mapred.InputFormat;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;

/** 
 * A base class for file-based {@link InputFormat}.
 * 
 * <p><code>FileInputFormat</code> is the base class for all file-based 
 * <code>InputFormat</code>s. This provides a generic implementation of
 * {@link #getSplits(JobConf, int)}.
 * Subclasses of <code>FileInputFormat</code> can also override the 
 * {@link #isSplitable(FileSystem, Path)} method to ensure input-files are
 * not split-up and are processed as a whole by {@link Mapper}s.
 */
public abstract class BinaryFileInputFormat<K, V> extends FileInputFormat<K, V> {

 // public static final Log LOG =    LogFactory.getLog(FileInputFormat.class);

//  private static final double SPLIT_SLOP = 1.0;   // 10% slop
  private static final double SPLIT_SLOP = 1.1;   // 10% slop
  
  private long minSplitSize = 1;
  private static final PathFilter hiddenFileFilter = new PathFilter(){
      public boolean accept(Path p){
        String name = p.getName(); 
        return !name.startsWith("_") && !name.startsWith("."); 
      }
    }; 
  protected void setMinSplitSize(long minSplitSize) {
    this.minSplitSize = minSplitSize;
  }

  public abstract RecordReader<K, V> getRecordReader(InputSplit split,
                                               JobConf job,
                                               Reporter reporter)
    throws IOException;

   /** Splits files returned by {@link #listStatus(JobConf)} when
   * they're too big.*/ 
  @SuppressWarnings("deprecation") 
  public InputSplit[] getSplits(JobConf job, int numSplits)
    throws IOException {
    FileStatus[] files = listStatus(job);
    
    long totalSize = 0;                           // compute total size
    for (FileStatus file: files) {                // check we have valid files
      if (file.isDir()) {
        throw new IOException("Not a file: "+ file.getPath());
      }
      totalSize += file.getLen();
    }

    long goalSize = totalSize / (numSplits == 0 ? 1 : numSplits);
    long minSize = Math.max(job.getLong("mapred.min.split.size", 1),
                            minSplitSize);

    // generate splits
    ArrayList<FileSplit> splits = new ArrayList<FileSplit>(numSplits);
    for (FileStatus file: files) {
      Path path = file.getPath();
      FileSystem fs = path.getFileSystem(job);
      long length = file.getLen();
      BlockLocation[] blkLocations = fs.getFileBlockLocations(file, 0, length);
      if ((length != 0) && isSplitable(fs, path)) { 
        long blockSize = file.getBlockSize();
        
        /* for binary file splitting */
        long recordSize = Math.max(job.getInt("io.file.binarybuffer.size", 1), minSplitSize);        
        long binaryGoalSize = computeBinaryGoalSize(splits.size(), recordSize, blockSize);        
        long splitSize = computeSplitSize(splits.size(), goalSize, binaryGoalSize, minSize, blockSize);
        
        long bytesRemaining = length;
        while(((double) bytesRemaining)/splitSize > SPLIT_SLOP) {        	
          int blkIndex = getBlockIndex(blkLocations, length-bytesRemaining);
          splits.add(new FileSplit(path, length-bytesRemaining, splitSize, 
                                   blkLocations[blkIndex].getHosts()));
          bytesRemaining -= splitSize;
          binaryGoalSize = computeBinaryGoalSize(splits.size(), recordSize, blockSize);            
          splitSize = computeSplitSize(splits.size(), goalSize, binaryGoalSize, minSize, blockSize);          
        }       
        if (bytesRemaining != 0) {
          splits.add(new FileSplit(path, length-bytesRemaining, bytesRemaining, 
                     blkLocations[blkLocations.length-1].getHosts()));
        }
      } else if (length != 0) {
        splits.add(new FileSplit(path, 0, length, blkLocations[0].getHosts()));
      } else { 
        //Create empty hosts array for zero length files
        splits.add(new FileSplit(path, 0, length, new String[0]));
      }
    }
 //   LOG.debug("Total # of splits: " + splits.size());
    return splits.toArray(new FileSplit[splits.size()]);
  }
  

  protected long computeBinaryGoalSize(long splitCnt, long recordSize, long blockSize){
	  int recordCnt = (int)(blockSize/recordSize);
	  return recordCnt * recordSize;
  }
  
  protected long computeSplitSize(long splitCnt, long goalSize, long binaryGoalSize, long minSize, long blockSize) {
	    return Math.max(minSize, Math.min(binaryGoalSize, blockSize));
  }
}

