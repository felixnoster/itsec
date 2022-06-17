package edu.hm.cs.ib.itsec.client;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;


public class Client {

    private static final int TAG_LENGTH_BIT = 128;

    private static final byte[] EMAIL = "ilie.doni@hm.edu".getBytes(StandardCharsets.UTF_8);

    private static final String PROVIDER = "BC";
    private Socket socket;
    private BufferedReader bufIn;
    private PrintWriter out;

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public static void main(final String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        Security.setProperty("crypto.policy", "unlimited");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        final Client c = new Client();
        generateKeyPair();
        c.run();
    }

    public static byte[] xorByteArray(byte[] input, int seqNumber) {
        byte[] param = ByteBuffer.allocate(input.length).putInt(8, seqNumber).array();
        return ByteUtils.xor(input, param);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }

    private void run() {
        try {
            connect();
            final var asymmetricResponse = doAsymmetricEncryption();
            final var secret = doSymmetricEncryption(asymmetricResponse);
            System.out.printf("Challenge complete! Your personal secret: %s %n", secret);
            disconnect();
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Connects the client to the server component.
     *
     * @throws IOException may throw an IOException e.g. if the host is unreachable.
     */
    private void connect() throws IOException {
        socket = new Socket("10.28.250.70", 9000);
        bufIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
    }

    /**
     * Closes all connections and disconnects the client
     *
     * @throws IOException may throw an IOException e.g. if the client died already.
     */
    private void disconnect() throws IOException {
        out.close();
        bufIn.close();
        socket.close();
    }

    /**
     * This method provides the communication for the asymmetric encrypted data.
     *
     * @param encryptedPublicKey Your own encrypted public key.
     * @param encryptedEmail     Your own encrypted email address.
     * @return the encrypted shared key for the symmetric encryption and the encrypted iv. (Must be decrypted again!)
     * @throws IOException May throw an IOException e.g. if the host is unreachable, reading data from the network failed or an invalid format.
     */
    private EncryptedAsymmetricResponse sendAsymmetricData(final byte[] encryptedPublicKey,
                                                           final byte[] encryptedEmail) throws IOException {
        out.println(Base64.toBase64String(encryptedEmail));
        out.println(Base64.toBase64String(encryptedPublicKey));
        EncryptedAsymmetricResponse response = new EncryptedAsymmetricResponse();
        response.SharedSecret = Base64.decode(bufIn.readLine());
        response.InitializationVector = Base64.decode(bufIn.readLine());
        return response;
    }

    /**
     * Sends the symmetric encrypted data to the server and returns your encrypted secret.
     *
     * @param encryptedEmail your encrypted E-Mail.
     * @return An byte array containing the encrypted secret.
     * @throws IOException May throw an IOException e.g. if the host is unreachable, reading data from the network failed or an invalid format.
     */
    private byte[] sendSymmetricData(final byte[] encryptedEmail) throws IOException {
        out.println(Base64.toBase64String(encryptedEmail));
        return Base64.decode(bufIn.readLine());
    }

    /**
     * Get the provided public key of the server.
     *
     * @return the public key.
     */
    private PublicKey getPubkey() throws Exception {
        final Path pubKey = Paths.get("client/data/public.key");
        try (final BufferedReader pubKeyreader = Files.newBufferedReader(pubKey)) {
            final KeyFactory kf = KeyFactory.getInstance("EC", PROVIDER);
            final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(pubKeyreader.readLine()));
            return kf.generatePublic(pubKeySpec);
        }
    }

    private AsymmetricResponse doAsymmetricEncryption() throws Exception {
        var returnValue = new AsymmetricResponse();

        /**
         * Your task is to implement this method.
         * The following steps must be implemented:
         *  - Generate an keypair using the curve25519
         *  - Encrypt the public component and your email using EC-IES with the public key of the server
         *  - Send the data to the server and receive the encrypted IV and shared key
         *  - Decrypt the data using EC-IES and your own private key and return the values
         */

        this.pair = generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();

        PublicKey serverPublicKey = getPubkey();

        Cipher cipher = Cipher.getInstance("ECIES", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedEmail = cipher.doFinal(EMAIL);

        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedPublicKey = cipher.doFinal(getPublicKey().getEncoded());

        EncryptedAsymmetricResponse value = sendAsymmetricData(encryptedPublicKey, encryptedEmail);

        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());

        returnValue.InitializationVector =  value.InitializationVector;
        returnValue.SharedSecret = new SecretKeySpec(value.SharedSecret, "ECIES");

        return returnValue;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    private String doSymmetricEncryption(AsymmetricResponse asymmetricResponse) throws Exception {
        String secret = null;

        /**
         * Your task is to implement this method.
         * The following steps must be implemented: 
         *  - Encrypt your email using AES-GCM, the provided shared key and IV
         *  - Send the data to the server and receive the encrypted shared secret
         *  - Decrypt the data using the shared key and IV
         *  - The IV get's XOR'ed with the (virtual) message number starting at 1
         *  - message number for communicating to server: 1
         *  - message number for response to client: 2
         */

//        Cipher cipher = Cipher.getInstance("AES");
//        cipher.init(Cipher.ENCRYPT_MODE, )
        return secret;
    }
}

/**
 * The (decrypted) content answered by the server containing the initial IV and the shared secret for the symmetric crypto.
 */
class AsymmetricResponse {

    /**
     * The initial IV. Must be XORed with the message number starting at 1.
     */
    public byte[] InitializationVector;

    /**
     * The secret key for the symmetric cryptography.
     */
    public SecretKey SharedSecret;

}

/**
 * The encrypted content answered by the server containing the initial IV and the shared secret for the symmetric crypto.
 */
class EncryptedAsymmetricResponse {

    /**
     * The encrypted IV.
     */
    public byte[] InitializationVector;

    /**
     * The encrypted key.
     */
    public byte[] SharedSecret;

}
