package clientserver;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.Base64;
import java.util.Map;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Asheet Tirkey
 */
public class HybrdSHA_SERVER extends UnicastRemoteObject implements HybridSHA_INT 
{
    HybrdSHA_SERVER() throws RemoteException
    {
	   super();
    }
 
    public static void main(String args[]) throws Exception
    {
    	try
        {
            Registry reg = LocateRegistry.createRegistry(Registry.REGISTRY_PORT);
            HybrdSHA_SERVER obj = new HybrdSHA_SERVER(); //remote object
            reg.rebind("rmi://localhost/cloud_service", obj); 
            System.out.println("\nServer Running...");
        }
        catch (RemoteException ex)
        {
            System.out.println(ex.getMessage());
        }
    }   
    
    //OVERIDE
    public String verifyIntegrity(byte[] encryptedMsg, String messageDigest,Map<String,Object> RSA_keys) throws RemoteException
    {
    	HybrdSHA_SERVER cl=new HybrdSHA_SERVER();
    	String skey="HQ0WE1RN2OIX5KL7"; //16 byte or 128 bits//
        Key AES_key=new SecretKeySpec(skey.getBytes(), "AES");
    	try
    	{
            //SEP 1 :
            //RSA
            PrivateKey privateKeyRSA = (PrivateKey) RSA_keys.get("private");
            String encryptedText = encryptMessage(AES_key.toString(), privateKeyRSA);
    	
            //STEP 2 :
            //SHA
            String digest=cl.procssDigest(encryptedText);
            System.out.println("\nSTEP 1 :");
            System.out.println("Public Key (AES_Key (Hex Form)) :"+bytesToHex(AES_key.getEncoded()));
            System.out.println("RSA encryption on AES KEY (encrypted key) :" + encryptedText);
            System.out.println("Calculated Message Digest:" + digest);
            System.out.println("\nReceived Message Digest:" + messageDigest);
            System.out.println("\nSTEP 2 Compare both the message digest:");
            System.out.println("\nBoth calculated and received digest are same,"
                        + "\n hence signature is verified and "
                        + "\n you can proceed with decyrpting the message");            
            //STEP 3 :
            //message decryption using AES
            if(digest.equals(messageDigest))
            {
                System.out.println("\nSTEP 3 :");
                System.out.println("Received Encrypted Message : "+ bytesToHex(encryptedMsg));
                String dt=cl.decrypt(encryptedMsg,AES_key);
	        System.out.println("Decrypted text : "+dt);      
            }
    	}
    	catch(Exception e) {}
    	return null;
    }
    
    //AES
    public String decrypt(byte[] pt,Key key) throws Exception
    {
        Cipher d=Cipher.getInstance("AES");
        d.init(Cipher.DECRYPT_MODE,key);
        byte[] decrypted=d.doFinal(pt);
        return new String(decrypted);
    }
   	
    //Encrypt using RSA private key
    public String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    } 
    
    //SHA to calculate message digest
    public String procssDigest(String input) throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(input.getBytes());
        byte[] digest = md.digest();
        StringBuffer sb = new StringBuffer();
        for (byte b : digest){
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
    
    protected static String  bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);
    }
}