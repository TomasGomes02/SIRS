package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;

/**
 * Encrypts an image with the RSA algorithm using a public key.
 * 
 * IMPORTANT: RSA has block size limitations (max 117 bytes for 1024-bit keys).
 * Only the first part of the image will be encrypted, and the output size
 * will be adjusted to fit the original image dimensions.
 * 
 * Usage: image-rsa-cipher [inputFile.png] [publicKeyFile] [outputFile.png]
 */
public class ImageRSACipher {

    public static void main(String[] args) throws Exception {

        if (args.length < 3) {
            System.err.println("This program encrypts an image file with RSA.");
            System.err.println("Usage: image-rsa-cipher [inputFile.png] [publicKeyFile] [outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String publicKeyFile = args[1];
        final String outputFile = args[2];

        RSACipherByteArrayMixer cipher = new RSACipherByteArrayMixer(Cipher.ENCRYPT_MODE, true);
        cipher.setParameters(publicKeyFile);
        ImageMixer.mix(inputFile, outputFile, cipher);

    }
}
