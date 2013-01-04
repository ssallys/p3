package p3.common.lib;

public class Bytes {
	
	/**
	 * 
	 * @param src
	 * @param srcPos
	 * @return
	 */
	public static int toInt(byte[] src, int srcPos){
		int dword = 0;
		for(int i=0;i<src.length-srcPos;i++){
			dword=(dword<<8) + (src[i + srcPos] & 0x7F);
			if((src[i + srcPos] & 0x80)==0x80)
				dword=dword + 128;				
		}
		return dword;
	}
	
	/**
	 * 
	 * @param src
	 * @return
	 */
	public static int toInt(byte[] src){
		return toInt(src, 0);
	}
	
	/**
	 * 
	 * @param src
	 * @return
	 */
	public static int toInt(byte src){
		byte[] b = new byte[1];
		b[0] = src;
		return toInt(b, 0);
	}
	
	/**
	 * 
	 * @param src
	 * @param srcPos
	 * @return
	 */
	public static long toLong(byte[] src, int srcPos){
		long dword = 0;
		for(int i=0;i<src.length-srcPos;i++){
			dword=(dword<<8) + (src[i + srcPos] & 0x7F);
			if((src[i + srcPos] & 0x80)==0x80)
				dword=dword + 128;				
		}
		return dword;
	}
	
	/**
	 * 
	 * @param src
	 * @return
	 */
	public static long toLong(byte[] src){
		return toLong(src, 0);
	}
}
