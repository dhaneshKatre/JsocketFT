import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.*;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class FileServer {
  private static ServerSocket ss = null;
  private static Socket socket = null;
  private static final int MAX_CLIENTS = 5;
  private static final int PORT = 1337;
  private static final ClientThread[] threads = new ClientThread[MAX_CLIENTS];

  public static void main(String[] args) {
    try {
      ss = new ServerSocket(PORT);
    } catch (IOException e) {
      System.out.println(e);
    }
    while (true) {
      try {
        socket = ss.accept();
        int i = 0;
        for (i = 0; i < MAX_CLIENTS; i++) {
          if (threads[i] == null) {
            (threads[i] = new ClientThread(socket)).start();
            break;
          }
        }
        if (i == MAX_CLIENTS) {
          PrintStream os = new PrintStream(socket.getOutputStream());
          os.println("Server too busy. Try later.");
          os.close();
          socket.close();
        }
      } catch (IOException r) {
        r.printStackTrace();
      }
    }
  }
}

class ClientThread extends Thread {
  DataInputStream is = null;
  PrintStream ps = null;
  Socket clientSocket = null;
  BufferedInputStream bis = null;
  OutputStream os = null;
  final File root = new File(System.getProperty("user.dir"));
  RSA rsa = null;
  AES aes = null;

  public void writeToClient(String msg) {
    ps.println(msg);
  }

  public ClientThread(Socket cs) {
    this.clientSocket = cs;
    this.rsa = new RSA();
    this.aes = new AES();
    try {
      is = new DataInputStream(cs.getInputStream());
      ps = new PrintStream(cs.getOutputStream());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void lS(String fName) {
    try {
      System.out.println(fName);
      final File folder = new File(fName);
      if (folder.isDirectory() && folder.exists()) {
        if (!(folder.list().length > 0)) {
          writeToClient("Directory is empty!");
          return;
        }
      }
      for (final File file : folder.listFiles()) {
        if (file.isDirectory())
          writeToClient("<DIR> " + file.getName());
        else
          writeToClient("<FILE> " + file.getName());
      }
    } catch (Exception r) {
      writeToClient("File does not exist.");
    }
  }

  public boolean sendFile(String fName) {
    try {
      System.out.println(fName);
      final File fileToSend = new File(fName);
      byte[] sendArray = new byte[(int) fileToSend.length()];
      bis = new BufferedInputStream(new FileInputStream(fileToSend));
      bis.read(sendArray, 0, sendArray.length);

      // *************AES*************//
      byte[] encryptedFile = aes.encrypt(sendArray);
      byte[] aesIv = aes.getIV();
      ByteBuffer byteBuffer = ByteBuffer.allocate(4 + aesIv.length + encryptedFile.length);
      byteBuffer.putInt(aesIv.length);
      byteBuffer.put(aesIv);
      byteBuffer.put(encryptedFile);
      byte[] bufferToSend = byteBuffer.array();
      writeToClient(bufferToSend.length + " bytes AES encrypted file incoming...");

      // ********Sending fie as byte array********//
      DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
      dOut.writeInt(bufferToSend.length);
      dOut.write(bufferToSend);
      return true;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  @SuppressWarnings("deprecation")
  public void run() {
    System.out.println(root);
    writeToClient("***Welcome to the Cloud***");
    writeToClient("Initializing Transfer Parameters...");
    writeToClient(rsa.getN().toString());
    writeToClient(rsa.getE().toString());
    writeToClient(rsa.getPhi().toString());
    byte[] secretKey = aes.getKey();
    byte[] finalCipherText = rsa.encrypt(secretKey);
    try {
      DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
      dOut.writeInt(finalCipherText.length);
      dOut.write(finalCipherText);
    } catch (Exception r) {
      r.printStackTrace();
    }
    while (true) {
      try {
        String request = is.readLine().trim();
        if (request.startsWith("quit")) {
          writeToClient("Hope to see you again! :-D Bye.");
          clientSocket.close();
          System.exit(0);
          break;
        } else if (request.startsWith("ls")) {
          try {
            lS(root.getAbsolutePath() + "/" + (request.split("[ \t]+"))[1]);
          } catch (ArrayIndexOutOfBoundsException r) {
            writeToClient("Path is not specified, showing root directory contents..");
            lS(root.getAbsolutePath());
          }
        } else if (request.startsWith("get")) {
          try {
            if (sendFile(root.getAbsolutePath() + "/" + (request.split("[ \t]+"))[1]))
              writeToClient("Transfer Successful!");
            else
              writeToClient("Transfer Failed!");
          } catch (ArrayIndexOutOfBoundsException e) {
            writeToClient("File is not specified!");
          }
        }
      } catch (IOException e) {
        e.printStackTrace();
      } catch (Exception r) {
        r.printStackTrace();
      }
    }
  }
}

class AES {
  private byte[] key, iv;
  private SecretKey secretKey;
  private SecureRandom secureRandom = new SecureRandom();

  public String getSaltString() {
    String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    StringBuilder salt = new StringBuilder();
    Random rnd = new Random();
    while (salt.length() < 16) {
      int index = (int) (rnd.nextFloat() * SALTCHARS.length());
      salt.append(SALTCHARS.charAt(index));
    }
    String saltStr = salt.toString();
    return saltStr;
  }

  public AES() {
    this.key = getSaltString().getBytes();
    this.iv = new byte[16];
    secretKey = new SecretKeySpec(key, "AES");
    secureRandom.nextBytes(iv);
  }

  public byte[] getIV() {
    return this.iv;
  }

  public byte[] getKey() {
    return this.key;
  }

  public byte[] encrypt(byte[] pt) {
    try {
      final Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
      cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
      byte[] ctb = cipher.doFinal(pt);
      ctb = Base64.getEncoder().encode(ctb);
      return ctb;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

}

class RSA {
  private BigInteger p;
  private BigInteger q;
  private BigInteger N;
  private BigInteger phi;
  private BigInteger e;
  private int bitlength = 1024;
  private Random r;

  public RSA() {
    r = new Random();
    p = BigInteger.probablePrime(bitlength, r);
    q = BigInteger.probablePrime(bitlength, r);
    N = p.multiply(q);
    phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    e = BigInteger.probablePrime(bitlength / 2, r);
    while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
      e.add(BigInteger.ONE);
  }

  public BigInteger getPhi() {
    return phi;
  }

  public BigInteger getN() {
    return N;
  }

  public BigInteger getE() {
    return e;
  }

  public byte[] encrypt(byte[] message) {
    return (new BigInteger(message)).modPow(e, N).toByteArray();
  }
}
