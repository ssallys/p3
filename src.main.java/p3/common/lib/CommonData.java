package p3.common.lib;

import java.util.StringTokenizer;

public class CommonData {
	
	public static int strToHex(String str){
		char[] arr = str.toCharArray();
		int i = 0;
		int val = 0;
		int tot = 0;

		if(str.startsWith("0x"))
			i = 2;
		while(i < arr.length){
			tot = (tot << 4);
			switch (arr[i]){
			case 'A':
			case 'a':
				val=10;
				break;
			case 'B':
			case'b':
				val=11;
				break;
			case 'C':
			case'c':
				val=12;
				break;
			case 'D':
			case'd':
				val=13;
				break;
			case 'E':
			case'e':
				val=14;
				break;
			case 'F':
			case'f':
				val=15;
				break;
			default:
				val = Integer.parseInt(String.valueOf(arr[i]));
			}			
			tot += val;
			i++;
		}
		return tot;
	}
	
	/**
	 * convert String-type IP address to Integer
	 * @param str
	 * @return
	 */
	public static int strIpToInt(String str){
		
		int val = 0;
		int i = 0;
		
		if(str==null) return val;
		
		StringTokenizer tok = new StringTokenizer(str, ".");
		int cnt = tok.countTokens();

		while(tok.hasMoreTokens()){
			val += Integer.parseInt(tok.nextToken()) << ((cnt-i-1)*8);
			i++;
		}
		return val;
	}
	
	/**
	 * convert Integer type IP address to String
	 * @param val
	 * @return
	 */
	public static String intTostrIp(int val){
		
		int i = 3;
		int curval = 0xff;
		String ip = null;
		
		ip = String.valueOf((val & 0xffffffffL)>>(i*8));
		
		while(i > 0){
			i--;
			ip += "."+ String.valueOf((val& 0xffffffffL)>>(8*i)&curval);
		}
		return ip;
	}
	
	/**
	 * convert Integer type IP address to String
	 * @param val
	 * @return
	 */
	public static String longTostrIp(long lval){
		
		int val = LongToInt(lval);
		int i = 3;
		int curval = 0xff;
		String ip = null;
		
		ip = String.valueOf((val & 0xffffffffL)>>(i*8));
		
		while(i > 0){
			i--;
			ip += "."+ String.valueOf((val & 0xffffffffL)>>(8*i) & curval);
		}
		return ip;
	}
		
	/**
	 * convert Integer type Subnet address to String
	 * @param val
	 * @return
	 */
	public static int intTostrSubnet(int val){		
		return 32-Integer.bitCount(val);
	}
	
	public static int longTostrSubnet(long lval){	
		int val = LongToInt(lval);
		return 32-Integer.bitCount(val);
	}
	
	public static int intTointSubnet(int val){		
		int i=0;
		int retval=0;
		while(i<(32-val)){
			retval = (retval << 1) | 0x01;
			i++;
		}
		return retval;
	}

	public static int longTointSubnet(long lval){		
		int i=0;
		int retval=0;	
		int val = LongToInt(lval);
		
		while(i<(32-val)){
			retval = (retval << 1) | 0x01;
			i++;
		}
		return retval;
	}
	
	public static long intToLong(int val){	
		return val & 0xffffffffL;	
	}
	
	public static int LongToInt(long val){	
		Long lval = new Long(val);
		return lval.intValue();
	}
}
