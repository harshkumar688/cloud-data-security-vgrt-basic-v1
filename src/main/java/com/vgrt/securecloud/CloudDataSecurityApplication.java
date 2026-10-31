package com.vgrt.securecloud;

import java.security.KeyPairGenerator;
import java.util.Base64;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CloudDataSecurityApplication {
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && "--generate-crypto-keys".equals(args[0])) {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(3072);
            var pair = generator.generateKeyPair();
            System.out.println("VGRT_RSA_PUBLIC_KEY=" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
            System.out.println("VGRT_RSA_PRIVATE_KEY=" + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
            return;
        }
        SpringApplication.run(CloudDataSecurityApplication.class, args);
    }
}
