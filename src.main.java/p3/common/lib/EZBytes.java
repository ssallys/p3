package p3.common.lib;

import java.nio.ByteOrder;

public class EZBytes {

 byte data[];
 int  size,current;
 
 //Function
 void EZBytes(){
	 Close(); 
}
 
 public EZBytes(int num_size){ 
	 EZBytes();
	 Init(num_size);
}
 
 public int getLength(){
	 return data.length;
 }
 
 void Close(){
	  data = null;
	  size = 0;
	  current = 0;
 }
 
 void Init(int num_size){
  data = new byte[num_size];
  size = num_size;
  current = 0;
 }
 
 public byte[] GetData(){ 
	 return data; 
}
 
 public void PutInt(int var){
  data[current++] = (byte)(var&0xff);
  data[current++] = (byte)((var>>8)&0xff);
  data[current++] = (byte)((var>>16)&0xff);
  data[current++] = (byte)((var>>24)&0xff);
 }
 
 public void PutShort(short var){
  data[current++] = (byte)(var&0xff);
  data[current++] = (byte)((var>>8)&0xff);
 }
 
 public void PutByte(byte var){
  data[current++] = var;
 }
 
 public void PutBytes(byte data[],int pos,int size){
  System.arraycopy(data,current,this.data,pos,size);
 }
 
 public void byteordering(){
	if (ByteOrder.nativeOrder().toString().equals("BIG_ENDIAN"))
		return;

	byte[] tmp = new byte[2];
	for(int i=0;i<data.length;i+=2){
		tmp[0] = data[i+1];
		tmp[1] = data[i];
		System.arraycopy(tmp,0,data,i,2);
	}
	 return;
 }
 
 public void PutInt(int pos,int var){
  current = pos;
  PutInt(var);
 }
 
 public void PutShort(int pos,short var){
  current = pos;
  PutShort(var);
 }
 public void PutByte(int pos,byte var){
  current = pos;
  PutByte(var);
 }
 
 public void PutBytes(int dest_pos,byte data[],int pos,int size){
  current = dest_pos;
  System.arraycopy(data,current,data,pos,size);
 }
 
public byte GetByte(int pos){
  return data[pos];
 }

public byte[] GetBytes(int pos){
	  int len = data.length - pos;
	  byte [] tmp = new byte[len];
	  System.arraycopy(data, pos, tmp, 0, tmp.length);
	  return tmp;
}

public byte[] GetBytes(int pos, int len){
	  byte [] tmp = new byte[len];
	  System.arraycopy(data, pos, tmp, 0, tmp.length);
	  return tmp;
}
 
public int GetInt(int pos){
  return (data[pos] & 0xff)<<24 |((data[pos + 1] & 0xff) << 16) |((data[pos + 2] & 0xff) << 8) |(data[pos + 3] & 0xff);
 }
 
public  short GetShort(int pos){
  return (short)((data[pos]&0xff)<<8|data[pos+1]&0xff);
 }
}



