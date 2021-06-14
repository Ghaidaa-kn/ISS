import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;
import java.io.Serializable;

public class Client implements Serializable {

    private static PrivateKey privateKey;
    public static PublicKey publicKey;
    private final String secretKey = "ssshhhhhhhhhhh!!!!";



    public static void main(String[] args) throws Exception {


        GenerateKeys generateKeys = new GenerateKeys();


        System.out.println("ENTER USERNAME  ");
        Scanner n_in = new Scanner(System.in);
        String user_name = n_in.next();
        System.out.println("ENTER PASSWORD  ");
        n_in = new Scanner(System.in);
        String password = n_in.next();


//        // keys to save in files
//        String publickey_str = generateKeys.getpublic(GenerateKeys.readPublicKey("public_client_" + user_name + ".txt"));
//        String privatekey_str = generateKeys.getprivate(GenerateKeys.readPrivateKey("private_client_" + user_name + ".txt"));

        File private_key = new File("private_client_" + user_name + ".txt");
        File public_key = new File("public_client_" + user_name + ".txt");

        // create public and private keys for new client
        if(!private_key.exists() && !public_key.exists()){
            generateKeys.Geenertateandstore("public_client_" + user_name + ".txt", "private_client_" + user_name + ".txt");
        }


        // read keys from there files
        publicKey = generateKeys.readPublicKey("public_client_" + user_name + ".txt");
        privateKey = generateKeys.readPrivateKey("private_client_" + user_name + ".txt");



        Socket socket_ca = new Socket("127.0.0.1", 20000);

        // send public key and name to CA
        ObjectOutputStream out_obj_ca = new ObjectOutputStream(socket_ca.getOutputStream());
        ObjectInputStream in_obj_ca = new ObjectInputStream(socket_ca.getInputStream());
        DataOutputStream out_st_ca = new DataOutputStream(socket_ca.getOutputStream());
        out_obj_ca.writeObject("cert");
        out_obj_ca.writeObject(user_name);
        out_obj_ca.writeObject(publicKey);

        String str = (String)in_obj_ca.readObject() ;
        String dec_str = RSA.decrypt(str , privateKey);
        out_obj_ca.writeObject(dec_str);

        // receive client certificate from CA
        X509Certificate cert = (X509Certificate)in_obj_ca.readObject();
        PublicKey public_key_CA = (PublicKey)in_obj_ca.readObject();
        System.out.println("public_key_CA " + public_key_CA);
        System.out.println("MY CERTIFICATE IS : " + cert.toString());



        // connect with Server
        Socket s = new Socket("127.0.0.1", 8888);
        try {

            // send client public key to the server
            ObjectOutputStream c_p = new ObjectOutputStream(s.getOutputStream());
            c_p.writeObject(publicKey);


            // recieve server public key from server
            ObjectInputStream s_publickey = new ObjectInputStream(s.getInputStream());
            PublicKey server_publickey = (PublicKey) s_publickey.readObject();


            // send client certificate to server
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());
            dos.writeUTF(user_name);
            oos.writeObject(cert);
            oos.writeObject(public_key_CA);
            System.out.println("I SEND MY CERTIFICATE TO SERVER ");

            // receive server certificate
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            DataInputStream dis = new DataInputStream(s.getInputStream());
            String msg = dis.readUTF();
            System.out.println("SERVER REPLY IS : " + msg);
            String name = dis.readUTF();
            X509Certificate server_cert = (X509Certificate)ois.readObject();
            PublicKey server_public_key_CA = (PublicKey)ois.readObject();
            //PublicKey publicverified = server_public_key_CA;
            System.out.println("I RECEIVE SERVER CERTIFICATE TO VERIFY IT ..  ");


            Socket socket_ca1 = new Socket("127.0.0.1" , 20000);
            ObjectOutputStream out_obj_ca1 = new ObjectOutputStream(socket_ca1.getOutputStream());
            ObjectInputStream in_obj_ca1 = new ObjectInputStream(socket_ca1.getInputStream());
            DataOutputStream out_st_ca1 = new DataOutputStream(socket_ca1.getOutputStream());
            out_obj_ca1.writeObject("check");
            out_obj_ca1.writeObject(server_cert);
            out_obj_ca1.writeObject(server_public_key_CA);
            out_obj_ca1.writeObject("server");
            String r1 = (String)in_obj_ca1.readObject();
            System.out.println(r1);
            Integer none = (Integer) in_obj_ca1.readObject();

            if(r1=="no"){
                System.out.println("public key and certificate is not ok ..........");
                s.close();
            }

            dos.writeUTF("CERTIFICATE TRUE ");

            //......................................................................................................


            ObjectOutputStream outobj = new ObjectOutputStream(s.getOutputStream());
            DataInputStream instream = new DataInputStream(s.getInputStream());
            DataOutputStream outstream = new DataOutputStream(s.getOutputStream());


            //Generate the session key
            SecretKey secret = keyGenerator();

            // encrypt and send the session key to the server
            String enc = RSA.encrypt(secret.toString(), server_publickey);
            outstream.writeUTF(enc);


            // receive the feedback
            String agreement = instream.readUTF();
            System.out.println(agreement);

            // digital signature
            DSA dsa = new DSA();
            KeyPair keypair = dsa.buildKeyPair();
            DSAPrivateKey dsaprivatekey = (DSAPrivateKey)keypair.getPrivate();
            DSAPublicKey dsapublicekey = (DSAPublicKey)keypair.getPublic();
            outobj.writeObject(dsapublicekey);


            // send log in details ( encrypted and signed data )
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            String enc_user_name = AES.encrypt(user_name , secret.toString());
            byte[] sign_user_name = RSA.encrypt_byte(DSA.sign(dsaprivatekey , user_name) , server_publickey);
            out.writeUTF(enc_user_name);
            outobj.writeObject(sign_user_name);
            String enc_password = AES.encrypt(password , secret.toString());
            byte[] sign_password = RSA.encrypt_byte(DSA.sign(dsaprivatekey , password) , server_publickey);
            out.writeUTF(enc_password);
            outobj.writeObject(sign_password);


            String what = "yes";

            while (!what.equals("no")) {

                IvParameterSpec iv = generateIv();
                // outobj.writeObj(iv);

                // Select the specific file's name
                System.out.println("ENTER THE NAME OF FILE YOU NEED : ");
                BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
                String file_name = input.readLine();


                // encrypt and send it  -  sign and send it
                outstream.writeUTF(AES.encrypt(file_name, secret.toString()));
                byte[] sign_f_name = RSA.encrypt_byte(DSA.sign(dsaprivatekey , file_name) , server_publickey);
                outobj.writeObject(sign_f_name);



                // receive the response of file from the server
                String feedback = AES.decrypt(instream.readUTF(), secret.toString());
                System.out.println(feedback);



                if (feedback.equals("THE FILE EXIST")) {

                    System.out.println("ENTER THE ACTION");

                    input = new BufferedReader(new InputStreamReader(System.in));
                    String the_action = input.readLine();

                    // encrypt the action and send it
                    outstream.writeUTF(AES.encrypt(the_action, secret.toString()));
                    //byte[] sign_action = DSA.sign(dsaprivatekey , the_action);
                    byte[] sign_action = RSA.encrypt_byte(DSA.sign(dsaprivatekey , the_action) , server_publickey);
                    outobj.writeObject(sign_action);


                    if (the_action.equals("view")) {
                        // receive the text and decrypt it
                        String text = instream.readUTF();
                        String dec1 = AES.decrypt(text, secret.toString());
                        System.out.println(dec1);


                    } else if (the_action.equals("edit")) {

                        String auth = instream.readUTF();
                        if (auth.equals("yes")) {
                            // receive the response
                            String res1 = AES.decrypt(instream.readUTF(), secret.toString());


                            System.out.println(res1);
                            // encrypt the new text and send it
                            input = new BufferedReader(new InputStreamReader(System.in));
                            String new_text = input.readLine();
                            String enc3 = AES.encrypt(new_text, secret.toString());
                            outstream.writeUTF(enc3);
                            //byte[] sign_text = DSA.sign(dsaprivatekey , new_text);
                            byte[] sign_text = RSA.encrypt_byte(DSA.sign(dsaprivatekey, new_text), server_publickey);
                            outobj.writeObject(sign_text);


                            // receive the response and decrypt it
                            String res2 = AES.decrypt(instream.readUTF(), secret.toString());
                            System.out.println(res2);
                        } else if (auth.equals("cant edit")) {
                            System.out.println("SORRY YOU CANT EDIT ");
                        }


                    } else{
                            System.out.println("GO OUT -_-");
                        }




                } else if (feedback.equals("THE FILE NOT EXIST")) {

                    System.out.println("ENTER YOUR TEXT");

                    input = new BufferedReader(new InputStreamReader(System.in));
                    String new_text = input.readLine();

                    String encryptedString = AES.encrypt(new_text, secret.toString());
                    outstream.writeUTF(encryptedString);
                    //byte[] sign_text = DSA.sign(dsaprivatekey , new_text);
                    byte[] sign_text = RSA.encrypt_byte(DSA.sign(dsaprivatekey , new_text) , server_publickey);
                    outobj.writeObject(sign_text);


                    String res = AES.decrypt(instream.readUTF(), secret.toString());
                    System.out.println(res);

                }

                System.out.println("ARE YOU WANT TO CONTINUE : YES - NO ? ");
                Scanner in_w = new Scanner(System.in);
                what = in_w.nextLine();
                outstream.writeUTF(what);


            }


            } catch (IOException ie) {
                ie.printStackTrace();
            }

        s.close();


        }

    public static SecretKey keyGenerator() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 256;

        keyGenerator.init(keyBitSize, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        return  secretKey;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }


}