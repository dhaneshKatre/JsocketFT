import java.io.*;
import java.net.*;

public class FileClient implements Runnable {

  private static Socket socket = null;
  private static PrintStream os = null;
  private static DataInputStream is = null;
  private static BufferedReader inputLine = null;
  private static boolean closed = false;
  private static final int PORT = 1337;
  private static final String root = "D:/NPLReceived/";
  private static String lastRequest;

  public static void main(String[] args) {
    try {
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
      } catch(IOException e) {
          e.printStackTrace();
      }
    }
  }

  public void getFile(String fName, Long size) {
    try {
      int bytesRead, current = 0;
      byte[] buffer = new byte[size.intValue()];
      DataInputStream ips = new DataInputStream(socket.getInputStream());
      BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(root + fName));
      while(size > 0 && (bytesRead = ips.read(buffer, 0, buffer.length)) != -1) {
        bos.write(buffer, 0, bytesRead);
        size -= bytesRead;
        bos.flush();
      }
      System.out.println("File " + fName + " downloaded successfully!");
    } catch(Exception r){
        System.out.println("Download Unsuccessful " + r.getMessage());
    }
  }

  public void run() {
    String response;
    try {
      while((response = is.readLine()) != null) {
        System.out.println(response);
        if(response.equalsIgnoreCase("Hope to see you again! :-D Bye."))
          System.exit(0);
        else if(response.contains(" bytes file incoming...")) {
          System.out.println("lastRequest: " + lastRequest);
          synchronized(this){getFile(lastRequest, Long.parseLong(response.split("[ \t]+")[0]));}
        }
      }
      closed = true;
    } catch(IOException e) {
        e.printStackTrace();
    }
  }
}
