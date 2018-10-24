import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.*;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.*;

public class FileClient implements Runnable {

  private static Socket socket = null;
  private static PrintStream os = null;
  private static DataInputStream is = null;
  private static BufferedReader inputLine = null;
  private static boolean closed = false;
  private static final int PORT = 1337;
  private static final String root = System.getProperty("user.dir");
  private static String lastRequest;
  private static byte[] key;
  private static RSA rsa;

  public static void main(String[] args) {
    try {
      rsa = new RSA();
      InetAddress cordAddress = InetAddress.getLocalHost(); // server's address
      socket = new Socket(cordAddress, PORT);
      inputLine = new BufferedReader(new InputStreamReader(System.in));
      os = new PrintStream(socket.getOutputStream());
      is = new DataInputStream(socket.getInputStream());
    } catch (IOException e) {
      e.printStackTrace();
    } catch (Exception r) {
      r.printStackTrace();
    }
    if (socket != null && os != null && is != null) {
      try {
        new Thread(new FileClient()).start();
        while (!closed) {
          lastRequest = inputLine.readLine().trim();
          os.println(lastRequest);
          lastRequest = lastRequest.split("[ \t]+")[1];
        }
        os.close();
        is.close();
        socket.close();
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  public void getAesFile(String fName, Long size) {
    try {
      DataInputStream dIn = new DataInputStream(socket.getInputStream());
      int length = dIn.readInt();
      if (length > 0) {
        byte[] m = new byte[length];
        dIn.readFully(m, 0, m.length);
        ByteBuffer buffer = ByteBuffer.wrap(m);
        int iv = buffer.getInt();
        byte[] iv2 = new byte[iv];
        buffer.get(iv2);
        byte[] ct = new byte[buffer.remaining()];
        buffer.get(ct);
        byte[] pt = AES.decode(key, ct, iv2);
        String[] name = fName.split("/");
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(root + "/" + name[name.length - 1]));
        bos.write(pt);
        System.out.println("Decryption Successful!");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // public void getEncryptedFile(String fName, Long size) {
  // try {
  // BigInteger[] data = new BigInteger[size.intValue()];
  // byte[] buffer = new byte[size.intValue()];
  // for (int i = 0; i < data.length; i++)
  // data[i] = new BigInteger(is.readLine());
  // System.out.println("File " + fName + " downloaded successfully!");
  // System.out.println("Decrypting...");
  // BigInteger privateKey = rsa.getPrivateKey();
  // for (int i = 0; i < data.length; i++)
  // buffer[i] = (byte) rsa.decode(privateKey, data[i]);
  // BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(root
  // + "\\" + fName));
  // bos.write(buffer);
  // System.out.println("Decryption Successful!");
  // } catch (Exception e) {
  // e.printStackTrace();
  // }
  // }

  @SuppressWarnings("deprecation")
  public void run() {
    String response;
    try {
      System.out.println(is.readLine());
      System.out.println(is.readLine());
      rsa.setN(new BigInteger(is.readLine()));
      rsa.setD(new BigInteger(is.readLine()), new BigInteger(is.readLine()));
      try {
        DataInputStream dIn = new DataInputStream(socket.getInputStream());
        int length = dIn.readInt();
        if (length > 0) {
          byte[] m = new byte[length];
          dIn.readFully(m, 0, m.length);
          key = rsa.decrypt(m);
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
      System.out.println("Done Initializing! Now you can request files.");
      while ((response = is.readLine()) != null) {
        System.out.println(response);
        if (response.equalsIgnoreCase("Hope to see you again! :-D Bye."))
          System.exit(0);
        else if (response.contains(" bytes AES encrypted file incoming...")) {
          System.out.println("lastRequest: " + lastRequest);
          synchronized (this) {
            getAesFile(lastRequest, Long.parseLong(response.split("[ \t]+")[0]));
          }
        }
      }
      closed = true;
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}

class AES {
  public static byte[] decode(byte[] key, byte[] ctb, byte[] iv) {
    try {
      SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
      final Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
      byte[] pt = cipher.doFinal(Base64.getDecoder().decode(ctb));
      return pt;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }
}

class RSA {
  private BigInteger N;
  private BigInteger d;

  public void setN(BigInteger n) {
    this.N = n;
  }

  public void setD(BigInteger e, BigInteger phi) {
    this.d = e.modInverse(phi);
  }

  public byte[] decrypt(byte[] message) {
    return (new BigInteger(message)).modPow(d, N).toByteArray();
  }
}
