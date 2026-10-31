package com.vgrt.securecloud.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CryptoService {
    private static final int NONCE_BYTES = 12;
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private final SecureRandom random = new SecureRandom();
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public CryptoService(@Value("${vgrt.crypto.public-key:}") String publicKeyBase64,
                         @Value("${vgrt.crypto.private-key:}") String privateKeyBase64) {
        try {
            if (publicKeyBase64.isBlank() || privateKeyBase64.isBlank())
                throw new IllegalStateException("Set VGRT_RSA_PUBLIC_KEY and VGRT_RSA_PRIVATE_KEY. Generate a pair with --generate-crypto-keys.");
            var factory = KeyFactory.getInstance("RSA");
            publicKey = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
            privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64)));
        } catch (IllegalStateException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("RSA key configuration is invalid", e); }
    }

    public EncryptedBlob encrypt(byte[] plaintext) throws Exception {
        var generator = KeyGenerator.getInstance("AES");
        generator.init(256, random);
        SecretKey key = generator.generateKey();
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce), random);
        byte[] ciphertext = aes.doFinal(plaintext);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey, OAEP, random);
        byte[] wrappedKey = rsa.doFinal(key.getEncoded());
        return new EncryptedBlob(ciphertext, Base64.getEncoder().encodeToString(nonce),
                Base64.getEncoder().encodeToString(wrappedKey), sha256(plaintext));
    }

    public byte[] decrypt(byte[] ciphertext, String nonceBase64, String wrappedKeyBase64, String expectedSha256) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, privateKey, OAEP);
        byte[] rawKey = rsa.doFinal(Base64.getDecoder().decode(wrappedKeyBase64));
        SecretKey key = new SecretKeySpec(rawKey, "AES");
        byte[] nonce = Base64.getDecoder().decode(nonceBase64);
        if (nonce.length != NONCE_BYTES) throw new SecurityException("Invalid encrypted object metadata");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] plaintext = aes.doFinal(ciphertext);
        if (!MessageDigest.isEqual(expectedSha256.getBytes(StandardCharsets.US_ASCII), sha256(plaintext).getBytes(StandardCharsets.US_ASCII)))
            throw new SecurityException("File integrity check failed");
        return plaintext;
    }

    private static String sha256(byte[] data) throws Exception {
        return HexFormatSupport.hex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    public record EncryptedBlob(byte[] ciphertext, String nonceBase64, String wrappedKeyBase64, String sha256) {}
}
