package clientserver;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.Map;
/**
 *
 * @author Asheet Tirkey
 */

//Remote interface
public interface HybridSHA_INT extends Remote //server implements this remote interface 
{
    //remote method
    public String verifyIntegrity(byte[] encryptedMsg, String messageDigest,Map<String,Object> keys) throws RemoteException;
    //this is a declaration and its definition is in Server class 
}