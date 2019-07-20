import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainClass {
	static Cipher	m_encrypter;

	static Cipher	m_decrypter;

	public static void main(String args[]) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		SecretKey key = KeyGenerator.getInstance("DES").generateKey();

		// for CBC; must be 8 bytes
		byte[] initVector = new byte[] { 0x10, 0x10, 0x01, 0x04, 0x01, 0x01, 0x01, 0x02 };

		AlgorithmParameterSpec algParamSpec = new IvParameterSpec(initVector);
		Cipher m_encrypter = Cipher.getInstance("DES/CBC/PKCS5Padding");
		Cipher m_decrypter = Cipher.getInstance("DES/CBC/PKCS5Padding");

		m_encrypter.init(Cipher.ENCRYPT_MODE, key, algParamSpec);
		m_decrypter.init(Cipher.DECRYPT_MODE, key, algParamSpec);

		FileInputStream fis = new FileInputStream("cipherTest.in");
		FileOutputStream fos = new FileOutputStream("cipherTest.out");
		int dataInputSize = fis.available();

		byte[] inputBytes = new byte[dataInputSize];
		fis.read(inputBytes);
		write(inputBytes, fos);
		fos.flush();
		fis.close();
		fos.close();

		String inputFileAsString = new String(inputBytes);
		System.out.println("INPUT FILE CONTENTS\n" + inputFileAsString + "\n");

		System.out.println("File encrypted and saved to disk\n");

		fis = new FileInputStream("cipherTest.out");

		byte[] decrypted = new byte[dataInputSize];
		read(decrypted, fis);

		fis.close();
		String decryptedAsString = new String(decrypted);

		System.out.println("DECRYPTED FILE:\n" + decryptedAsString + "\n");

	}

	public static void write(byte[] bytes, OutputStream out) throws Exception {
		CipherOutputStream cos = new CipherOutputStream(out, m_encrypter);
		cos.write(bytes, 0, bytes.length);
		cos.close();
	}

	public static void read(byte[] bytes, InputStream in) throws Exception {
		CipherInputStream cis = new CipherInputStream(in, m_decrypter);
		int pos = 0, intValue;

		while ((intValue = cis.read()) != -1)
		{
			bytes[pos] = (byte) intValue;
			pos++;
		}
	}

}