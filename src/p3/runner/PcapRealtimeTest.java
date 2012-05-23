package p3.runner;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.util.ToolRunner;

import p3.hadoop.common.packet.PcapRec;
import p3.hadoop.packet.analyzer.P3CoralProgram;

public class PcapRealtimeTest {
	
	static JobConf conf = new JobConf(P3CoralProgram.class);

	static String getFilterFromFile(String filename){		
		return null;
	}
	
	
	static void printUsage() {
		System.out.println("PcapRealtimeTest [-s <frequency>] [-p] <inDir> <outDir>");
		ToolRunner.printGenericCommandUsage(System.out);
		return;
	}
	
	public static void main(String[] args) throws Exception{
		
		List<String> other_args = new ArrayList<String>();
		for (int i = 0; i < args.length; ++i) {
			try {
				if ("-s".equals(args[i])) {
		        	conf.setFloat("mapred.snapshot.frequency", Float.parseFloat(args[++i]));
		        	conf.setBoolean("mapred.map.pipeline", true);
				} else if ("-p".equals(args[i])) {
					conf.setBoolean("mapred.map.pipeline", true);
				} else {
					other_args.add(args[i]);
				}
			} catch (NumberFormatException except) {
				System.out.println("ERROR: Integer expected instead of "
						+ args[i]);
				printUsage();
			} catch (ArrayIndexOutOfBoundsException except) {
				System.out.println("ERROR: Required parameter missing from "
						+ args[i - 1]);
				printUsage();
			}
		}
		// Make sure there are exactly 3 parameters left.
		if (other_args.size() < 1) {
			System.out.println("ERROR: Wrong number of parameters: "
					+ other_args.size() + " instead of 1.");
			printUsage();
		}
		FileInputFormat.setInputPaths(conf, other_args.get(0));
		FileOutputFormat.setOutputPath(conf, new Path(other_args.get(1)));

		P3CoralProgram hcoral = new P3CoralProgram(conf);			
		hcoral.startRealTest();
	}	
}