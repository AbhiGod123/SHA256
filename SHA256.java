import java.math.BigInteger;
import java.lang.*;
import java.util.Arrays;
import java.nio.ByteBuffer;

public class SHA256 {
	public static int sum1(int X)
	{	
		return (Integer.rotateRight(X,6) ^ Integer.rotateRight(X,11) ^ Integer.rotateRight(X,25));
	}
	
	public static int sum0(int X)
	{	
		return (Integer.rotateRight(X,2) ^ Integer.rotateRight(X,13) ^ Integer.rotateRight(X,22));
	}
	
	public static int ShR(int X, int n){
		return (X >> n);
	}
	
	public static int Maj(int x, int y, int z)
	{	
		return ((x & y) ^ (x & z) ^ (y & z));
	}
	
	public static int Ch(int x, int y, int z)
	{	
		return ((x & y) ^ ((~x) & z));
	}
	
	public static int phi0(int X)
	{
		return (Integer.rotateRight(X,7) ^ Integer.rotateRight(X,18) ^ ShR(X,3));
	}
	
	public static int phi1(int X)
	{
		return (Integer.rotateRight(X,17) ^ Integer.rotateRight(X,19) ^ ShR(X,10));
	}
	
	public static byte[] padM(byte[] M){
		String bytes = "";
		
		for(int i=0;i<M.length;++i){
			bytes += String.format("%8s", Integer.toBinaryString((M[i] + 256) % 256))
                         .replace(' ', '0');
		}
		
		final String initbytes = bytes;
		
		final int l = bytes.length(); //should be 24
		
		final int k = (512 + 448 - (l % 512 + 1)) % 512;

		bytes+=1;
		
		for(int i=0;i<k+32;++i)
			bytes+=0;
		
		final String s = Integer.toBinaryString(l);
		
		for(int i=0;i<32-s.length();++i)
		    bytes+=0;
		    
		    bytes+=s;
	
		return convertToBytes(bytes);
	}
	
	public static byte[] convertToBytes(String s){
	    byte[] bytes = new byte[s.length()/8];
	    
	    for(int i=0;i<bytes.length;++i){
	        bytes[i] = (byte)Integer.parseInt(s.substring(i * 8,i * 8 + 8), 2); 
	    }
	    
	    return bytes;
	}
	
	final static int[] K = 
	{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2	
	};
	
	public static int[] toIntArray(byte[] bytes){
	    if (bytes.length % Integer.BYTES != 0) {
            throw new IllegalArgumentException("byte array length");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes);

        int[] result = new int[bytes.length / Integer.BYTES];
        for (int i = 0; i < result.length; ++i) {
            result[i] = buf.getInt();
        }

        return result;
	}

	public static byte[] hash(byte[] oldM)
	{
		int[] M = toIntArray(padM(oldM)); //pads the bytes to be a multiple of 512
		
		final int N = M.length/16;
		
		int[] W = new int[64];
		
		int[] H = new int[8];
		H[0] = 0x6a09e667;
		H[1] = 0xbb67ae85;
		H[2] = 0x3c6ef372;
		H[3] = 0xa54ff53a;
		H[4] = 0x510e527f;
		H[5] = 0x9b05688c;
		H[6] = 0x1f83d9ab;
		H[7] = 0x5be0cd19;
		
		for(int t=0;t<N;++t){
			//construct blocks Wi
    		for(int i=0;i<16;++i){
    		    W[i] = M[i];
	        }//sets W for the first 16 values
	
    		for(int i=16;i<64;++i){
    			W[i] = phi1(W[i-2]) + W[i-7] + phi0(W[i-15]) + W[i-16];
    		}//sets W for the last 48 values
    			
			//set values
			int a = H[0];
			int b = H[1];
			int c = H[2];
			int d = H[3];
			int e = H[4];
			int f = H[5];
			int g = H[6];
			int h = H[7];
			
			for(int i=0;i<64;++i){
				int T1 = h + sum1(e) + Ch(e,f,g) + K[i] + W[i];
				int T2 = sum0(a) + Maj(a,b,c);
				
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}
			
			H[0] = H[0] + a;
			H[1] = H[1] + b;
			H[2] = H[2] + c;
			H[3] = H[3] + d;
			H[4] = H[4] + e;
			H[5] = H[5] + f;
			H[6] = H[6] + g;
			H[7] = H[7] + h;
		}
		
		System.out.println("To Hex");
		for(int i=0;i<8;++i){
		    String hex = Integer.toHexString(H[i]);
		    System.out.print(hex + ", ");
		}//prints in hex values
		
		return toByteArray(H);
	}
	
	public static byte[] toByteArray(int[] ret){
	    byte[] bytes = new byte[ret.length * 4];
	    
	    for(int i=0;i<ret.length;++i){
	        int newi = i * 4;
	        bytes[newi + 0] = (byte)(ret[i]>>24);
	        bytes[newi + 1] = (byte)(ret[i]>>16);
	        bytes[newi + 2] = (byte)(ret[i]>>8);
	        bytes[newi + 3] = (byte)(ret[i]);
	    }
	    
	    return bytes;
	}
	
	public static void main(String[] args){
		byte[] bytes= {61,62,63};
		
		byte[] data = SHA256.hash(bytes);
			
		System.out.println(data.length);
	}
}


