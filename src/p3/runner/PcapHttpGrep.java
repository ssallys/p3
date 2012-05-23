package p3.runner;

import java.util.Calendar;
import java.util.Random;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.*;
import org.apache.hadoop.mapred.lib.*;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

import p3.hadoop.common.packet.PcapRec;
import p3.hadoop.mapred.PcapInputFormat;
import p3.hadoop.packet.analyzer.P3CoralProgram;
import p3.hadoop.packet.searcher.HttpRegexMapper;

/* Extracts matching regexs from input files and counts them. */
public class PcapHttpGrep extends Configured implements Tool {
  private PcapHttpGrep() {}                               // singleton

//  static JobConf conf = new JobConf(P3CoralProgram.class);
	
  public int run(String[] args) throws Exception {
	int period = 60;
	String[] end = null;
	long cap_start = 0;
	long cap_end = 0;
	boolean rtag = false; 
	char argtype = 0;
	
    if (args.length < 4) {
        System.out.println("PcapHttpGrep  <inDir> <outDir> <regex> [<group>] -b<start timestamp>");
        ToolRunner.printGenericCommandUsage(System.out);
        return -1;
      }

    JobConf grepJob = new JobConf(getConf(), PcapHttpGrep.class);
	grepJob.addResource("p3-default.xml");
	
    int i=3;
    
    try {
      
      grepJob.setJobName("grep-search");

      FileInputFormat.setInputPaths(grepJob, args[0]);

      grepJob.setMapperClass(HttpRegexMapper.class);
      grepJob.set("mapred.mapper.regex", args[2]);
/*      if (args.length == 5){
        grepJob.set("mapred.mapper.regex.group", args[3]);
        i++;
      }*/
	while(i<args.length){
		if(args[i].startsWith("-")){
			
			argtype = args[i].charAt(1);
			switch (argtype){
				
			case 'B': case 'b':					
				String[] begin = args[i].substring(2).trim().split("-");
				if(begin.length<3)
					begin = args[i].substring(2).trim().split("/");
				if (begin.length == 3) {
					Calendar cal = Calendar.getInstance( );
					cal.set(Integer.parseInt(begin[0]),
							Integer.parseInt(begin[1]),Integer.parseInt(begin[2]));
					cal.add(Calendar.MONTH, -1);
					cal.add(Calendar.DATE, -1);
					cap_start = Math.round(cal.getTimeInMillis()/1000);
				}
				break;
				
			case 'E': case 'e':
				end = args[i].substring(2).trim().split("-");
				if(end.length<3)
					end = args[i].substring(2).trim().split("/");
				if (end.length == 3) {
					Calendar cal = Calendar.getInstance( );
					cal.set(Integer.parseInt(end[0]),
							Integer.parseInt(end[1]),Integer.parseInt(end[2]));
					cal.add(Calendar.MONTH, -1);
					cal.add(Calendar.DATE, 1);
					cap_end = Math.round(cal.getTimeInMillis()/1000);
				}
				break;
			
			case 'P': case 'p':
				period = Integer.parseInt(args[i].substring(2).trim());
				grepJob.setInt("pcap.record.rate.interval", period);
				break;		
			}					
		}
		i++;
	}
    grepJob.setLong("pcap.file.captime.min", cap_start);
    grepJob.setLong("pcap.file.captime.max", cap_end);
      FileOutputFormat.setOutputPath(grepJob, new Path(args[1]));    
      grepJob.setInputFormat(PcapInputFormat.class);    
      grepJob.setOutputFormat(TextOutputFormat.class);
      grepJob.setOutputKeyClass(Text.class);
      grepJob.setOutputValueClass(Text.class);

      FileSystem fs = FileSystem.get(grepJob);
      // delete any output that might exist from a previous run of this job
      if (fs.exists(FileOutputFormat.getOutputPath(grepJob))) {
        fs.delete(FileOutputFormat.getOutputPath(grepJob), true);
      }      
      JobClient.runJob(grepJob);
    }
    finally {
//      FileSystem.get(grepJob).delete(tempDir, true);
    }
    return 0;
  }

  public static void main(String[] args) throws Exception {
    int res = ToolRunner.run(new Configuration(), new PcapHttpGrep(), args);
    System.exit(res);
  }

}
