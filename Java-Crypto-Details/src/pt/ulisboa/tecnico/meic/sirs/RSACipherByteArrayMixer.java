package pt.ulisboa.tecnico.meic.sirs;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import javax.crypto.Cipher;

/**
 * RSA cipher implementation as a ByteArrayMixer.
 *
 * IMPORTANT: RSA has strict block size limitations (117 bytes input for
 * 1024-bit keys with PKCS1Padding). This implementation processes data
 * block-by-block and adjusts the output to match the input array size for
 * compatibility with image processing.
 */
public class RSACipherByteArrayMixer implements ByteArrayMixer {

  private String keyFile;
  private int opmode;
  private boolean usePublicKey; // true for encryption, false for decryption

  public RSACipherByteArrayMixer(int opmode, boolean usePublicKey) {
    this.opmode = opmode;
    this.usePublicKey = usePublicKey;
  }

  public void setParameters(String keyFile) { this.keyFile = keyFile; }

  @Override
  public byte[] mix(byte[] byteArray, byte[] byteArray2) throws Exception {
    Key key;
    if (usePublicKey) {
      key = RSAKeyGenerator.readPublicKey(keyFile);
    } else {
      key = RSAKeyGenerator.readPrivateKey(keyFile);
    }

    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    System.out.println(cipher.getProvider().getInfo());

    int inputBlockSize;
    int outputBlockSize;

    if (opmode == Cipher.ENCRYPT_MODE) {
      // For 1024-bit RSA with PKCS1Padding: max input is 117 bytes
      inputBlockSize = 117;
      outputBlockSize = 128; // Always 128 bytes output
      System.out.println("RSA encrypting with public key...");
    } else {
      // For decryption: input must be 128 bytes, produces up to 117 bytes
      inputBlockSize = 128;
      outputBlockSize = 117;
      System.out.println("RSA decrypting with private key...");
    }

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    int inputLength = byteArray.length;

    // Process complete blocks only
    int blocksProcessed = 0;
    for (int i = 0; i + inputBlockSize <= inputLength; i += inputBlockSize) {
      byte[] chunk = new byte[inputBlockSize];
      System.arraycopy(byteArray, i, chunk, 0, inputBlockSize);

      cipher.init(opmode, key);
      byte[] processedChunk = cipher.doFinal(chunk);
      outputStream.write(processedChunk);
      blocksProcessed++;
    }

    System.out.println("Processed " + blocksProcessed + " RSA blocks");

    byte[] result = outputStream.toByteArray();

    // For image compatibility, adjust output to match input size
    // This may truncate encrypted data or pad decrypted data
    if (result.length != byteArray.length) {
      System.out.println("Warning: Size changed from " + byteArray.length +
                         " to " + result.length +
                         " bytes. Adjusting for image format.");

      byte[] adjustedResult = new byte[byteArray.length];
      int copyLength = Math.min(result.length, byteArray.length);
      System.arraycopy(result, 0, adjustedResult, 0, copyLength);
      return adjustedResult;
    }

    return result;
  }
}
