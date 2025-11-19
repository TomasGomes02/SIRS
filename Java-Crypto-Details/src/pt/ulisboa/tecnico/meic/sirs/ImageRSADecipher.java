package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;

/**
 * Decrypts an image with the RSA algorithm using a private key.
 * 
 * IMPORTANT: RSA has block size limitations (128 bytes for 1024-bit keys).
 * Only the first part of the image will be decrypted, and the output size
 * will be adjusted to fit the original image dimensions.
 * 
 * Usage: image-rsa-decipher [inputFile.png] [privateKeyFile] [outputFile.png]
 */
public class ImageRSADecipher {

    public static void main(String[] args) throws Exception {

        if (args.length < 3) {
            System.err.println("This program decrypts an image file with RSA.");
            System.err.println("Usage: image-rsa-decipher [inputFile.png] [privateKeyFile] [outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String privateKeyFile = args[1];
        final String outputFile = args[2];

        RSACipherByteArrayMixer cipher = new RSACipherByteArrayMixer(Cipher.DECRYPT_MODE, false);
        cipher.setParameters(privateKeyFile);
        ImageMixer.mix(inputFile, outputFile, cipher);

    }
}
