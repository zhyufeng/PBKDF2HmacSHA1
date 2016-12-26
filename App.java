package com.zhyufeng.pbkdf2;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Hello world!
 *
 */
public class App 
{
	 //TEST
    public static void main(String[] args){
    	String password = "password";
    	String salt = "XaIs9vQgmLujKHZG4/B3dNTbeP2PyaVKySTirZznBrE=";
    	String pbkstr = "PBKDF2$sha1$98$XaIs9vQgmLujKHZG4/B3dNTbeP2PyaVKySTirZznBrE=$2DX/HZDTojVbfgAIdozBi6CihjWP1+akYnh/h9uQfIVl6pLoAiwJe1ey2WW2BnT+";
    	String ciphertext;
    	Boolean match;
    	
    	try {
    		//test case of mosquitto-auth-plug pbkdf2-check.c
    		ciphertext = PBKDF2HmacSHA1.encryptedPassword(password,salt);
			System.out.println(ciphertext); 
			System.out.println("Checking password ["+"password"+"] for "+"pbkstr");
			match = ciphertext.equals(pbkstr);
			System.out.println("match: "+match );
			
    		salt = PBKDF2HmacSHA1.generateSalt();
    		System.out.println("salt: "+salt );
			String storedPassword = ciphertext;
			System.out.println("Checking passwordOriginal ["+password+"] for "+storedPassword);
			match = PBKDF2HmacSHA1.validatePassword(password,storedPassword);
			System.out.println("match: "+match );
			
			password = "password1";
			System.out.println("Checking passwordOriginal ["+password+"] for "+storedPassword);
			match = PBKDF2HmacSHA1.validatePassword(password,storedPassword);
			System.out.println("match: "+match );
			
	    } catch (NoSuchAlgorithmException e) {  
	    	 System.out.println("NoSuchAlgorithmException"); 
	    } catch (InvalidKeySpecException e) {
	    	 System.out.println("InvalidKeySpecException");
		} 
    	
    }
}
