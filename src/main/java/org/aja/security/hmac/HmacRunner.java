package org.aja.security.hmac;



import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Mac;
import org.apache.commons.codec.binary.Base64;

public class HmacRunner {

    public static void main(String...args) throws Exception {
        HmacRunner runner = new HmacRunner();
        System.out.println("Equal: " + runner.createHmac());

    }

    private boolean createHmac() throws Exception {
        String secret = "secret key";
        String message = "Secret message that I would not like anyone to see except receiver";

        Mac mac = Mac.getInstance("HmacSHA256"); //HMAC algorithms that go by the names of HMAC-MD5, HMAC-SHA1, or HMAC-SHA256.
        SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");//secret and algorithm
        mac.init(secret_key); //initialize mac
        String hash = Base64.encodeBase64String(mac.doFinal(message.getBytes())); //create Hash
        String cryptoString  = new String( mac.doFinal(), "UTF8");
        System.out.println(cryptoString); //print cryptoString
        System.out.println(hash); //print hash
        System.out.println( "\n" + mac.getProvider().getInfo() );//provider

        //validate encrypted message
        Mac mac1 = Mac.getInstance("HmacSHA256");
        mac1.init(secret_key);
        String cryptoString1  = new String( mac1.doFinal(), "UTF8") ;


        //validate hash
        String hash1 = Base64.encodeBase64String(mac1.doFinal(message.getBytes())); //create Hash
        if (!hash.equals(hash1)) {
            return false;
        }

        return cryptoString.equals(cryptoString1);

    }
}
