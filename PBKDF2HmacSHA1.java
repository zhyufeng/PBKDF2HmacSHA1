package com.zhyufeng.pbkdf2;


import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
    public static String encryptedPassword(String password, String salt) throws NoSuchAlgorithmException,  
            InvalidKeySpecException {  
    	String ciphertext;
    	
    	KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), PBKDF2_ITERATIONS, HASH_KEY_LEN);  
        SecretKeyFactory sf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);  
        String key = new String( Base64.encodeBase64( sf.generateSecret(spec).getEncoded() ) );
        
        ciphertext = TAG + SEPARATOR + ALGORITHM_TAG + SEPARATOR + PBKDF2_ITERATIONS + SEPARATOR + salt + SEPARATOR + key;
        return ciphertext;
    }  
    
    
    
    /** 
     * validate Encrypted Password
     *  
     * @param originalPassword 
     * @param storedPassword 
     * @return 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeySpecException 
     */  
    public static boolean validatePassword(String originalPassword,  
            String storedPassword) throws NoSuchAlgorithmException,  
            InvalidKeySpecException {
    	    //split storedpassword
    		String[] parts = storedPassword.split("\\$");
    		String pbk = parts[0];
    		String sha = parts[1];
    		int iter = Integer.parseInt(parts[2]);
    		String salt  = parts[3];
    		String keyStored   = parts[4];
    		String shaAlgorithm;
    		
    		switch(sha){
    			case "sha1":
    				shaAlgorithm = "PBKDF2WithHmacSHA1";
    				break;
    			case "sha256":
    				shaAlgorithm = "PBKDF2WithHmacSHA256";
    				break;
    			case "sha512":
    				shaAlgorithm = "PBKDF2WithHmacSHA512";
    				break;
    			default:
    				throw new NoSuchAlgorithmException();
    		}
    			
    		//create Encrypted key
    		KeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt.getBytes(), iter, HASH_KEY_LEN);  
            SecretKeyFactory sf = SecretKeyFactory.getInstance(shaAlgorithm);
            String keyOriginal = new String( Base64.encodeBase64( sf.generateSecret(spec).getEncoded() ) );    
            
    		boolean mach= keyOriginal.equals(keyStored);	   	
    	    return mach ; 
    }
    
    /** 
     * Generate a random salt  
     *  
     * @return 
     * @throws NoSuchAlgorithmException 
     */  
    public static String generateSalt() throws NoSuchAlgorithmException {  
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");  
        byte[] salt = new byte[SALT_LEN];  
        random.nextBytes(salt);  
  
        return new String(Base64.encodeBase64(salt)); 
    }  
    
    
}
