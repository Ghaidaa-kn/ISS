//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Vector;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CA {
    private static ServerSocket serverSocket;
    static Vector<String> users = new Vector();
    static Vector<CA.ClientHandler> clients = new Vector();
    static Vector<X509Certificate> certs = new Vector();
    static KeyPair pair;
    static HashMap<X509Certificate , Integer> auth = new HashMap<X509Certificate , Integer>();

    public CA() {
    }

    public static void main(String... args) throws IOException {
        System.out.println("CERTIFICATE CENTER STARTED");

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            pair = keyGen.generateKeyPair();
        } catch (Exception var4) {
        }

        serverSocket = new ServerSocket(20000);

        while(true) {
            while(true) {
                try {
                    Socket socketToClient = serverSocket.accept();
                    CA.ClientHandler clientHandler = new CA.ClientHandler(socketToClient);
                    clients.add(clientHandler);
                } catch (Exception var5) {
                    var5.printStackTrace();
                }
            }
        }
    }

    static class ClientHandler extends Thread {
        String user;
        ObjectInputStream input;
        ObjectOutputStream output;
        X509Certificate cert = null;
        boolean c = false;

        ClientHandler(Socket socket) throws Exception {
            try {
                this.input = new ObjectInputStream(socket.getInputStream());
                this.output = new ObjectOutputStream(socket.getOutputStream());
            } catch (IOException var12) {
            }

            String type = (String) input.readObject();
            if (type.equals("check")){

                    X509Certificate certVerified = (X509Certificate) input.readObject();
                    PublicKey publicKey_cl = (PublicKey) this.recieve();
                    String user_name = (String) this.recieve();
                    File f = new File("CA_" + user_name);
                    if (auth.containsKey(certVerified))

                        try {
                            if(f.exists()){
                                FileInputStream fis = new FileInputStream(f);
                                ObjectInputStream ois = new ObjectInputStream(fis);
                                X509Certificate existcert = (X509Certificate) ois.readObject();

                                certVerified.verify(publicKey_cl);
                                if(existcert.equals(certVerified)){
                                    this.send("ok");
                                    this.output.writeObject(auth.get(certVerified));
                                }
                            }

                        } catch (InvalidKeyException e) {
                            this.send("no");

                        } catch (NoSuchAlgorithmException |
                                NoSuchProviderException |
                                SignatureException |
                                CertificateException e) {

                        }

                } else if(type.equals("cert")) {

                this.user = this.recieve().toString();
                CA.users.add(this.user);
                PublicKey publicKey1 = (PublicKey) this.recieve();

                // to check of public key
                String text = "this text to verify your publick key";
                String enc_text = RSA.encrypt(text, publicKey1);
                this.send(enc_text);
                String dec_text = (String) this.recieve();

                if (text.equals(dec_text)) {
                    GenerateKeys generate = new GenerateKeys();
                    String s = generate.getpublic(publicKey1);
                    String s1 = generate.getpublic(CA.pair.getPublic());
                    System.out.println(this.user + " PUBLIC KEY :  " + s);
                    System.out.println(" CA PUBLIC KEY  :      "+ s1);
                    boolean yes = true;
                    if (yes) {
                        File f = new File("CA_" + this.user);
                        if (!f.exists()) {
                            System.out.println("GENERATED NEW DIGITAL CERTIFICATE FOR THE CLIENT " + this.user);
                            Security.addProvider(new BouncyCastleProvider());
                            this.cert = X509.generateV1Certificate(publicKey1, CA.pair.getPrivate(), this.user);
                            FileOutputStream fos = new FileOutputStream(f);
                            ObjectOutputStream oos = new ObjectOutputStream(fos);
                            oos.writeObject(this.cert);
                            oos.close();
                            int x = 0 + (int) (Math.random() * 2);
                            auth.put(this.cert, x);
                        } else {
                            System.out.println(this.user + " HAS DIGITAL CERTIFICATE BEFORE");

                            try {
                                File f2 = new File("CA_" + this.user);
                                FileInputStream fis = new FileInputStream(f2);
                                ObjectInputStream ois = new ObjectInputStream(fis);
                                X509Certificate certVerified = (X509Certificate) ois.readObject();
                                this.cert = certVerified;
                                ois.close();
                            } catch (Exception var11) {
                            }
                        }

                        this.send(this.cert);
                        this.send(CA.pair.getPublic());
                        CA.certs.add(this.cert);
                    }

                }
            }

//             else {
//                System.err.println("REPLYING ...");
//            }

        }




        void setUser(String user) {
            this.user = user;
        }

        Object recieve() {
            Object o = new Object();

            try {
                o = this.input.readObject();
            } catch (IOException var3) {
                return null;
            } catch (ClassNotFoundException var4) {
            }

            return o;
        }

        void send(Object text) {
            try {
                this.output.writeObject(text);
            } catch (IOException var3) {
            }

        }


        public void run() {
        }
    }
}
