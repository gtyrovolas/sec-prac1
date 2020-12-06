import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

public class BeastAttack
{


    public static void main(String[] args) throws Exception
    {
	Scanner sc = new Scanner(System.in);
        
	byte[] ciphertext = new byte[1024]; 
	byte[] prevCipher = new byte[1024];

	callEncrypt(null, 0, ciphertext);	    

	// the ciphertext is 64 bytes long, hence the padded plaintext is 56 bytes long
	// the IV is approximately 5 times the timestamp in milliseconds
	// when run through ssh the code below gives approximately 5000 difference in the IV
	
	int lsb = (ciphertext[5] & 0xFF) * 256 * 256 + (ciphertext[6] & 0xFF) * 256 + (ciphertext[7] & 0xFF), plsb = 0;
	
	while(true){
	TimeUnit.MILLISECONDS.sleep(996);
	plsb = lsb;
	prevCipher = ciphertext;
	int length = callEncrypt(null, 0, ciphertext);	    
	
	for(int i = 0; i < 8; i++)
	{
	    System.out.print(String.format("%02x ", ciphertext[i]));
	}

	for(int j = 8; j < length; j++)
	{
	    System.out.print(String.format("%02x", ciphertext[j]));
	}
	System.out.println("");    
	
	lsb = (ciphertext[5] & 0xFF) * 256 * 256 + (ciphertext[6] & 0xFF) * 256 + (ciphertext[7] & 0xFF);
	int diff = (lsb - plsb + 256 * 256 * 256) % (256 * 256 * 256);
	System.out.println("Difference of IV: " + diff + " " +  String.format("%#x", diff));

	}

    }
    


    // a helper method to call the external programme "encrypt" in the current directory
    // the parameters are the plaintext, length of plaintext, and ciphertext; returns length of ciphertext
    static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException
    {
	HexBinaryAdapter adapter = new HexBinaryAdapter();
	Process process;
	
	// run the external process (don't bother to catch exceptions)
	if(prefix != null)
	{
	    // turn prefix byte array into hex string
	    byte[] p=Arrays.copyOfRange(prefix, 0, prefix_len);
	    String PString=adapter.marshal(p);
	    process = Runtime.getRuntime().exec("./encrypt "+PString);
	}
	else
	{
	    process = Runtime.getRuntime().exec("./encrypt");
	}

	// process the resulting hex string
	String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
	byte[] c=adapter.unmarshal(CString);
	System.arraycopy(c, 0, ciphertext, 0, c.length); 
	return(c.length);
    }
}
