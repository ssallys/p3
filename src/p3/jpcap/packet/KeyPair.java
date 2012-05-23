package p3.jpcap.packet;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.WritableComparable;

public class KeyPair implements WritableComparable<KeyPair> {
	
	private BytesWritable first;
	private Text second;
	
	public KeyPair() {
		set(new BytesWritable(), new Text());
	}
	
	public KeyPair(byte[] first, String second) {
		set(new BytesWritable(first), new Text(second));
	}
	
	public KeyPair(BytesWritable first, Text second) {
		set(first, second);
	}
	
	public void set(BytesWritable first, Text second) {
		this.first = first;
		this.second = second;
	}
	
	
	public BytesWritable getFirst() {
		return first;
	}

	public void setFirst(BytesWritable first) {
		this.first = first;
	}

	public Text getSecond() {
		return second;
	}

	public void setSecond(Text second) {
		this.second = second;
	}

	@Override
	public void write(DataOutput out) throws IOException {
		first.write(out);
		second.write(out);
	}
	
	@Override
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
		if (o instanceof KeyPair) {
			KeyPair tp = (KeyPair) o;
			return first.equals(tp.first) && second.equals(tp.second);
		}
		return false;
	}
	
	@Override
	public String toString() {
		return first + "\t" + second;
	}
	
	@Override
	public int compareTo(KeyPair tp) {
		int cmp = first.compareTo(tp.first);
		if (cmp != 0) {
			return cmp;
		}			
		return second.compareTo(tp.second);
	}
}