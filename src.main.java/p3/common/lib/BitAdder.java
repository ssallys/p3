package p3.common.lib;
/**
 * bit adder
 * @author user
 *
 */
public final class BitAdder {
	
	/*** original function ***/
	public static byte[] addBinary(byte[] b1, byte[]b2, int dataLen){
		
		byte[] result = new byte[dataLen];
		int idx = dataLen;
		
		int out, cout;
		int bit_pos, byte_pos;
		out = cout =  bit_pos = 0;
		Integer sum = 0;	
		byte_pos = dataLen;
		
		while (--idx >= 0 ){
			while(bit_pos < 8){
				out = (((b1[idx] >> bit_pos) ^ (b2[idx] >> bit_pos)) ^ cout) & 0x01;
				cout = ((((b1[idx] >> bit_pos)^(b2[idx] >> bit_pos)) & cout) | (b1[idx] >> bit_pos & b2[idx] >> bit_pos)) & 0x01;
				sum |= out << bit_pos;
				bit_pos++;					
			}			
			result[--byte_pos]= sum.byteValue();
			sum = bit_pos = 0;
		}						
		return result;
	}
	
	/*** original function ***/
	public static int addBinary(byte[] b1, byte[]b2){
		
		int dataLen = 4;
		int result = 0;
		int idx = dataLen;
		
		int out, cout;
		int bit_pos, byte_pos;
		out = cout =  bit_pos = 0;
		Integer sum = 0;	
		byte_pos = dataLen;
		
		while (--idx >= 0 ){
			while(bit_pos < 8){
				out = (((b1[idx] >> bit_pos) ^ (b2[idx] >> bit_pos)) ^ cout) & 0x01;
				cout = ((((b1[idx] >> bit_pos)^(b2[idx] >> bit_pos)) & cout) | (b1[idx] >> bit_pos & b2[idx] >> bit_pos)) & 0x01;
				sum |= out << bit_pos;
				bit_pos++;					
			}			
			result |= sum << ((dataLen-1-idx)*8);
			sum = bit_pos = 0;
		}						
		return result;
	}
}
