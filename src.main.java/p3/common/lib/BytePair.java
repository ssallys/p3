package p3.common.lib;

import java.io.*;
import org.apache.hadoop.io.*;

public class BytePair implements WritableComparable<BytePair> {
	
	private BytesWritable first;
	private BytesWritable second;
	
	public BytePair() {
		set(new BytesWritable(), new BytesWritable());
	}
	
	public BytePair(byte[] first, byte[] second) {
		set(new BytesWritable(first), new BytesWritable(second));
	}
	
	public BytePair(BytesWritable first, BytesWritable second) {
		set(first, second);
	}
	
	public void set(BytesWritable first, BytesWritable second) {
		this.first = first;
		this.second = second;
	}
	
	public BytesWritable getFirst() {
		return first;
	}
	
	public BytesWritable getSecond() {
		return second;
	}
	
	public void write(DataOutput out) throws IOException {
		first.write(out);
		second.write(out);
	}
	
	public void readFields(DataInput in) throws IOException {
		first.readFields(in);
		second.readFields(in);
	}
	
	@Override
	public int hashCode() {
		return first.hashCode() * 163 + second.hashCode();
	}
	
	@Override
	public boolean equals(Object o) {
		if (o instanceof BytePair) {
			BytePair tp = (BytePair) o;
			return first.equals(tp.first) && second.equals(tp.second);
		}
		return false;
	}
	
	@Override
	public String toString() {
		return first + "\t" + second;
	}
	public int compareTo(BytePair tp) {
		int cmp = first.compareTo(tp.first);
		if (cmp != 0) {
			return cmp;
		}
		return second.compareTo(tp.second);
	}

	public static int compare(BytesWritable first, BytesWritable second) {
		return first.compareTo(second);
	}
		
	public static int compare2(BytesWritable first, BytesWritable second) {
		return 0;
	}
	
	public BytePair clone(BytePair bp){
		bp.first.set(first);
		bp.second.set(second);
		return bp;
	}
}