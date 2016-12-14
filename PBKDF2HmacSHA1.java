package com.zhyufeng.pahomqtt;


import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * 
 * 
 * @author Zhang Yufeng
 * @email  yfyfzh@163.com
 * @version 0.1,2016-12-14
 * 
 */

public class PBKDF2HmacSHA1 {
	/** 
     * algorithm
     */  
	public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
	
	/** 
     * salt Length 
     */  
    public static final int SALT_LEN = 12; 
    
    /** 
     * Key length 
     */  
    public static final int HASH_KEY_LEN = 64*6;  
  
    /** 
     * iterations  
     */  
    public static final int PBKDF2_ITERATIONS = 98;  
    
    /** 
     * separator 
     */  
    public static final String SEPARATOR = "$"; 
    
    /** 
     * tag algorithm
     */  
    public static final String TAG = "PBKDF2"; 
    
    /**  
     * tag  hash algorithm
     */  
    public static final String ALGORITHM_TAG = "sha1";
    
    /** 
     * create Encrypted Password
     *  
     * @param password 
     * @param salt 
     * @return 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeySpecException 
     */  
    public static String getEncryptedPassword(String password, String salt) throws NoSuchAlgorithmException,  
            InvalidKeySpecException {  
    	String ciphertext;
    	
    	KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), PBKDF2_ITERATIONS, HASH_KEY_LEN);  
        SecretKeyFactory sf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);  
        String key = new String( Base64.encodeBase64( sf.generateSecret(spec).getEncoded() ) );
        
        ciphertext = TAG + SEPARATOR + ALGORITHM_TAG + SEPARATOR + PBKDF2_ITERATIONS + SEPARATOR + salt + SEPARATOR + key;
        return ciphertext;
    }  
    
    
    //TEST
    public static void main(String[] args){
    	String password = "password";
    	String salt = "XaIs9vQgmLujKHZG4/B3dNTbeP2PyaVKySTirZznBrE=";
    	String pbkstr = "PBKDF2$sha1$98$XaIs9vQgmLujKHZG4/B3dNTbeP2PyaVKySTirZznBrE=$2DX/HZDTojVbfgAIdozBi6CihjWP1+akYnh/h9uQfIVl6pLoAiwJe1ey2WW2BnT+";
    	String ciphertext;
    	Boolean match;
    	
    	try {
    		ciphertext = getEncryptedPassword(password,salt);
			System.out.println(ciphertext); 
			System.out.println("Checking password ["+"password"+"] for "+"pbkstr");
			match = ciphertext.equals(pbkstr);
			System.out.println("match: "+match );
			
	    } catch (NoSuchAlgorithmException e) {  
	    	 System.out.println("NoSuchAlgorithmException"); 
	    } catch (InvalidKeySpecException e) {
	    	 System.out.println("InvalidKeySpecException");
		} 
    	
    }
    
}
