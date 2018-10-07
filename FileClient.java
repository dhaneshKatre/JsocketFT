import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.*;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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
  private static byte[] key = new byte[16];
  private static RSA rsa;
  public static void main(String[] args) {
    try {
      rsa = new RSA();
      InetAddress cordAddress = InetAddress.getLocalHost(); //server's address
      socket = new Socket(cordAddress, PORT);
      inputLine = new BufferedReader(new InputStreamReader(System.in));
      os = new PrintStream(socket.getOutputStream());
      is = new DataInputStream(socket.getInputStream());
    } catch(IOException e) {
        e.printStackTrace();
    } catch(Exception r) {
        r.printStackTrace();
    }
    if(socket != null && os != null && is != null) {
      try {
        new Thread(new FileClient()).start();
        while(!closed) {
          lastRequest = inputLine.readLine().trim();
          os.println(lastRequest);
          lastRequest = lastRequest.split("[ \t]+")[1];
        }
        os.close();
        is.close();
        socket.close();
      } catch(Exception e) {
          e.printStackTrace();
      }
    }
  }

  public void getKey() {
    try {
      BigInteger privateKey = rsa.getPrivateKey();
      BigInteger[] data = new BigInteger[16];
      for(int i=0;i<data.length;i++)
        data[i] = new BigInteger(is.readLine());
      System.out.println("Decoding Key!");
      for(int i=0;i<data.length;i++)
        key[i] = (byte) rsa.decode(privateKey, data[i]);
      System.out.println("Initialization Successful!");
    } catch(Exception r) {
      r.printStackTrace();
    }
  }

  public void getAesFile(String fName, Long size) {
    try {
      byte[] ctArr = new byte[size.intValue()];
      DataInputStream dis = new DataInputStream(socket.getInputStream());
      dis.read(ctArr);
      dis.close();
      ByteBuffer buffer = ByteBuffer.wrap(ctArr);
      int iv = buffer.getInt();
      if(iv < 12 || iv >= 16)
        throw new IllegalArgumentException("Wrong ivL");
      byte[] iv2 = new byte[iv];
      buffer.get(iv2);
      byte[] cipherTxt = new byte[buffer.remaining()];
      buffer.get(cipherTxt);
      byte[] pt = AES.decode(key, cipherTxt, iv2);
      BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(root +"/"+ fName));
      bos.write(pt);
      System.out.println("Decryption Successful!");
    } catch(Exception r) {
      r.printStackTrace();
    }
  }

  // public void getEncryptedFile(String fName, Long size) {
  //   try {
  //     BigInteger[] data = new BigInteger[size.intValue()];
  //     byte[] buffer = new byte[size.intValue()];
  //     for(int i=0;i<data.length;i++)
  //       data[i] = new BigInteger(is.readLine());
  //     System.out.println("File " + fName + " downloaded successfully!");
  //     System.out.println("Decrypting...");
  //     BigInteger privateKey = rsa.getPrivateKey();
  //     for(int i=0;i<data.length;i++)
  //       buffer[i] = (byte)rsa.decode(privateKey, data[i]);
  //     BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(root +"\\"+ fName));
  //     bos.write(buffer);
  //     System.out.println("Decryption Successful!");
  //   } catch(Exception e) {
  //     e.printStackTrace();
  //   }
  // }

  // public void getFile(String fName, Long size) {
  //   try {
  //     int bytesRead, current = 0;
  //     byte[] buffer = new byte[size.intValue()];
  //     DataInputStream ips = new DataInputStream(socket.getInputStream());
  //     BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(root +"\\"+ fName));
  //     while(size > 0 && (bytesRead = ips.read(buffer, 0, buffer.length)) != -1) {
  //       bos.write(buffer, 0, bytesRead);
  //       size -= bytesRead;
  //       bos.flush();
  //     }
  //     System.out.println("File " + fName + " downloaded successfully!");
  //   } catch(Exception r){
  //       System.out.println("Download Unsuccessful " + r.getMessage());
  //   }
  // }

  public void run() {
    String response;
    try {
      System.out.println(is.readLine());
      System.out.println(is.readLine());
      BigInteger n = new BigInteger(is.readLine());
      BigInteger phi = new BigInteger(is.readLine());
      BigInteger publicKey = new BigInteger(is.readLine());
      rsa.setN(n);
      rsa.setPhi(phi);
      rsa.setPublicKey(publicKey);
      rsa.generatePrivate(publicKey);
      getKey();
      while((response = is.readLine()) != null) {
        System.out.println(response);
        if(response.equalsIgnoreCase("Hope to see you again! :-D Bye."))
          System.exit(0);
        else if(response.contains(" bytes AES encrypted file incoming...")) {
          System.out.println("lastRequest: " + lastRequest);
          synchronized(this){getAesFile(lastRequest, Long.parseLong(response.split("[ \t]+")[0]));}
        }
      }
      closed = true;
    } catch(IOException e) {
        e.printStackTrace();
    }
  }
}

class AES {
  public static byte[] decode(byte[] key, byte[] ctb, byte[] iv) {
    try {
      SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new GCMParameterSpec(128, iv));
      byte[] pt = cipher.doFinal(java.util.Base64.getDecoder().decode(ctb));
      return pt;
    } catch(Exception e) {
      e.printStackTrace();
      return null;
    }
  }
}

class RSA {
    private BigInteger publicKey, phi, privateKey, n;

    public void generatePrivate(BigInteger publicKey) {
        this.privateKey = publicKey.modInverse(phi);
    }

    public BigInteger getPrivateKey() {
      return this.privateKey;
    }

    public void setPhi(BigInteger phi) {
      this.phi = phi;
    }

    public void setPublicKey(BigInteger publicKey) {
      this.publicKey = publicKey;
    }

    public void setN(BigInteger n) {
      this.n = n;
    }

    public int decode(BigInteger privateKey, BigInteger ct) {
        try {
            return (ct.pow(privateKey.intValue()).mod(n)).intValue();
        } catch(ArithmeticException e) {
            e.printStackTrace();
            return -99;
        }
    }
}
