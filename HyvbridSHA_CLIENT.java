package clientserver;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.xml.bind.DatatypeConverter;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;	
/**
 *
 * @author Asheet Tirkey
 */
public class HyvbridSHA_CLIENT extends AES_CLIENT
{
    public static void main(String args[]) throws Exception
    {
        System.out.println("\nClient Running...");
        //Step 1
        //AES public key for encrypting
        String skey="HQ0WE1RN2OIX5KL7"; //16 byte or 128 bits//
        Key AES_key=new SecretKeySpec(skey.getBytes(), "AES");
       
        Scanner sc=new Scanner(System.in);
           
        System.out.println("Enter the Plain text : ");
        String pt=sc.nextLine();
                
       	//Encryption AES
        byte[] ct=AES_CLIENT.encrypt(pt, AES_key);            
        System.out.println("Cipher text : "+ct);
            
        /*Decyption AES
        String dt=AESU.decrypt(ct, key);
        System.out.println("Decrypted text : "+dt);*/      
             
        //STEP 2
        //RSA for integrity
        RSA_CLIENT rsau = new RSA_CLIENT();
        Map<String, Object> RSA_keys = rsau.getRSAKeys(); // Generate public and private keys using RSA
        PrivateKey privateKeyRSA = (PrivateKey) RSA_keys.get("private");
        //PublicKey publicKeyRSA = (PublicKey) keys.get("public");
 
        String encryptedText = encryptMessage(AES_key.toString(), privateKeyRSA);
        //String decryptedText = decryptMessage(encryptedText, publicKeyRSA);
        
        //STEP 3
        //SHA for RSA-Encrypted AES key
        SHA_CLIENT  sha=new SHA_CLIENT();
        String digest=sha.procssDigest(encryptedText);

        System.out.println("\nSTEP 1: ");
        System.out.println("Public Key (AES_Key (Hex Form)) :"+bytesToHex(AES_key.getEncoded()));
        System.out.println("\nSTEP 2: ");
        System.out.println("RSA encryption on AES KEY (Public Key) : " + encryptedText);
        System.out.println("\nSTEP 3: ");       
        System.out.println("Message Digest(SHA) of encrypted key :" + digest);
        
        System.out.println("\nPlain text : "+pt); 
        System.out.println("Encrypted Text (Hex Form):"+bytesToHex(ct));
        System.out.println("\n Encrypted Text and Message Digest is send to the Server");        
        
        //sending data
        Registry reg = LocateRegistry.getRegistry("localhost",Registry.REGISTRY_PORT);
        HybridSHA_INT intobj = (HybridSHA_INT) reg.lookup("rmi://localhost/cloud_service"); 
        intobj.verifyIntegrity(ct, digest, RSA_keys);
        //keys--> for generating RSA key to encrypt the AES public key
    }
}
class AES_CLIENT extends RSA_CLIENT{
    
    public static byte[] encrypt( String ct,Key key) throws Exception
    {
        Cipher c=Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE,key);
        byte[] encVal=c.doFinal(ct.getBytes());
        return encVal;
    }
     public static String decrypt(byte[] pt,Key key) throws Exception
    {
        Cipher d=Cipher.getInstance("AES");
        d.init(Cipher.DECRYPT_MODE,key);
        byte[] decrypted=d.doFinal(pt);
        return new String(decrypted);
    }
    protected static String  bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);
    }

}
class RSA_CLIENT extends SHA_CLIENT
{
     // Get RSA keys. Uses key size of 2048.
    public Map<String,Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
 
        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
                
        return keys;
    }
 
    // Encrypt using RSA private key
    public static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    } 
    
    // Decrypt using RSA public key
    public static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }
}
class SHA_CLIENT
{	
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
}