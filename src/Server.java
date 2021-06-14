import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.io.Serializable;
import java.util.Map;


public class Server {

    private static PrivateKey privateKey;
    public static PublicKey publicKey;
    private final String secretKey = "ssshhhhhhhhhhh!!!!";
    public static HashMap<String , PublicKey>  clients_public_key = new HashMap<>(40);



    public static void main(String[] args) throws Exception {


        //Generate public and private keys
        GenerateKeys generateKeys = new GenerateKeys();


        publicKey = generateKeys.readPublicKey("server_public_key.txt");
        privateKey = generateKeys.readPrivateKey("server_private_key.txt");


        try {


            ServerSocket server = new ServerSocket(8888);
            int id = 0;
            System.out.println("SERVER STARTED");


            while (true) {

                id++;
                String client_name = "client_" + id;
                //server accept the client connection request
                Socket serverClient = server.accept();
                System.out.println(" -->> " + "CLIENT_" + id + " STARTED!");
                //send  the request to a separate thread
                Handler sct = new Handler(serverClient, id, publicKey, privateKey, client_name );
                sct.start();

            }

        } catch (Exception e) {
            System.out.println(e);
        }


    }


    static class Handler extends Thread implements Serializable {
        Socket serverClient;
        int client_id;
        PublicKey s_publicKey;
        PrivateKey s_privateKey;
        PublicKey client_publickey;
        String client_name;


        Handler(Socket inSocket, int id, PublicKey server_publicKey, PrivateKey server_privateKey, String c_name ) {
            serverClient = inSocket;
            client_id = id;
            s_publicKey = server_publicKey;
            s_privateKey = server_privateKey;
            client_name = c_name;
        }


        public void run() {

            try {


                // receive client public key
                ObjectInputStream c_publickey = new ObjectInputStream(serverClient.getInputStream());
                client_publickey = (PublicKey) c_publickey.readObject();
                Server.clients_public_key.put(client_name, client_publickey);


                // send server public key
                ObjectOutputStream s_publickey = new ObjectOutputStream(serverClient.getOutputStream());
                s_publickey.writeObject(s_publicKey);



                // receive the certificate from client
                ObjectInputStream ois = new ObjectInputStream(serverClient.getInputStream());
                DataInputStream dis = new DataInputStream(serverClient.getInputStream());
                String name = dis.readUTF();
                X509Certificate client_cert = (X509Certificate)ois.readObject();
                PublicKey client_public_key_CA = (PublicKey)ois.readObject();
                System.out.println("I RECEIVE " + name + " CERTIFICATE TO VERIFY IT ..");

                System.out.println(name + " CERTIFICATE IS : " + client_cert);

                // CSR
                Socket socket_ca = new Socket("127.0.0.1", 20000);
                ObjectOutputStream out_obj_ca = new ObjectOutputStream(socket_ca.getOutputStream());
                ObjectInputStream in_obj_ca = new ObjectInputStream(socket_ca.getInputStream());
                DataOutputStream out_st_ca = new DataOutputStream(socket_ca.getOutputStream());
                out_obj_ca.writeObject("check");
                out_obj_ca.writeObject(client_cert);
                out_obj_ca.writeObject(client_public_key_CA);
                out_obj_ca.writeObject(name);
                String r1 = (String)in_obj_ca.readObject();
                Integer auth = (Integer) in_obj_ca.readObject();
                System.out.println("AUTHORIZATION OF EDIT : " + auth);
                System.out.println(r1);
                if(r1=="no"){
                    System.out.println("PUBLIC KEY AND CERTIFICATE IS NOT OK ");
                    serverClient.close();
                }

                Socket socket_ca1 = new Socket("127.0.0.1", 20000);
                ObjectOutputStream out_obj_ca1 = new ObjectOutputStream(socket_ca1.getOutputStream());
                ObjectInputStream in_obj_ca1 = new ObjectInputStream(socket_ca1.getInputStream());
                DataOutputStream out_st_ca1 = new DataOutputStream(socket_ca1.getOutputStream());

                out_obj_ca1.writeObject("cert");
                out_obj_ca1.writeObject("server");
                out_obj_ca1.writeObject(publicKey);

                // to CA verify my public key
                String str = (String)in_obj_ca1.readObject() ;
                String dec_str = RSA.decrypt(str , s_privateKey);
                out_obj_ca1.writeObject(dec_str);

                X509Certificate cert = (X509Certificate)in_obj_ca1.readObject();
                PublicKey public_key_CA = (PublicKey)in_obj_ca1.readObject();
                System.out.println("public_key_CA " + public_key_CA);
                System.out.println("MY CERTIFICATE IS : " + cert.toString());



                // send server certificate to client
                ObjectOutputStream oos = new ObjectOutputStream(serverClient.getOutputStream());
                DataOutputStream dos = new DataOutputStream(serverClient.getOutputStream());
                dos.writeUTF("CERTIFICATE TRUE");
                dos.writeUTF("server");
                oos.writeObject(cert);
                oos.writeObject(public_key_CA);
                System.out.println("I SEND MY CERTIFICATE TO " + name);

                String msg = dis.readUTF();
                System.out.println(name +" REPLY IS : " + msg);

//..........................................................................................................

                DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
                LocalDateTime now = LocalDateTime.now();
               // System.out.println(dtf.format(now));

//...........................................................................................................



                ObjectInputStream inobj = new ObjectInputStream(serverClient.getInputStream());
                DataOutputStream outstream = new DataOutputStream(serverClient.getOutputStream());
                DataInputStream instream = new DataInputStream(serverClient.getInputStream());

                // receive the session key and decrypt it
                // receive the new session key and decrypti it
                String dec1 = RSA.decrypt(instream.readUTF(), privateKey);


                // send feedback
                outstream.writeUTF("\t\t\t\t\t\t\t THE SESSION KEY HAS RECEIVED ");

                // receive DSA public key
                DSAPublicKey dsapublickey = (DSAPublicKey)inobj.readObject();



                // receive client details for log in and verify it
                DSA dsa = new DSA();
                DataInputStream in = new DataInputStream(serverClient.getInputStream());
                String user_name = AES.decrypt(in.readUTF() , dec1);
                byte[] sign_user_name = RSA.decrypt_byte((byte[]) inobj.readObject() , s_privateKey);
                String password = AES.decrypt(in.readUTF(),dec1);
                byte[] sign_password = RSA.decrypt_byte((byte[]) inobj.readObject() , s_privateKey);


                if(check_user(user_name , password)) {

                    boolean find = false ;
                    // verify data with database
                    for(Map.Entry<String, String> entry: get_client_data().entrySet()) {

                        if(dsa.verify(dsapublickey , entry.getKey() , sign_user_name) && dsa.verify(dsapublickey , entry.getValue() , sign_password)){
                            System.out.println("VERIFY FOE UASERNAME AND PASSWORD IS OK ");
                            find = true;
                        }
                    }
                    if(!find){
                        System.out.println("VERIFY FOE UASERNAME AND PASSWORD IS NOT OK ");
                        serverClient.close();
                    }


                } else {
                    // insert new client to database
                    System.out.println("YOU ARE A NEW CLIENT ");
                    insert_client(user_name , password , client_publickey.toString());
                    System.out.println("REGISTER DONE ");

                    // verify data with ecncrypted data
                    if(dsa.verify(dsapublickey , user_name , sign_user_name) && dsa.verify(dsapublickey , password , sign_password)){
                        System.out.println("VERIFY FOR USERNAME AND PASSWORD IS OK ");
                    }else {
                        System.out.println("VERIFY FOR USERNAME AND PASSWORD IS NOT OK");
                        serverClient.close();
                    }

                }


                String reply = "yes";

                    while (!reply.equals("no")) {

                        //IvParameterSpec iv = (IvParameterSpec) inobj.readObj();

                        // receive the file name (first req) and decrypt it
                        String fname = AES.decrypt(instream.readUTF(), dec1);
                        byte[] sign_fname = RSA.decrypt_byte((byte[]) inobj.readObject() , s_privateKey);

                        if(DSA.verify(dsapublickey , fname , sign_fname)) {
                            System.out.println("VERIFY FOR FILE NAME IS OK ");
                        }else {
                            System.out.println("VERIFY FOR FILE NAME IS NOT OK");
                            serverClient.close();
                        }


                        File file = new File("C:\\Users\\ASUS\\Desktop\\SOCKET_2(1)\\Files\\" + fname + ".txt");


                        if (file.exists()) {


                            // encrypt and send the response
                            String res1 = AES.encrypt("THE FILE EXIST", dec1);
                            outstream.writeUTF(res1);


                            // receive the action and decrypt it
                            String action = AES.decrypt(instream.readUTF(), dec1);
                            byte[] sign_action = RSA.decrypt_byte((byte[]) inobj.readObject() , s_privateKey);

//                            if(DSA.verify(dsapublickey , action , sign_action)) {
//                                System.out.println("VERIFY FOR ACTION IS OK ");
//                            }else {
//                                System.out.println("VERIFY FOR ACTION IS NOT OK");
//                                serverClient.close();
//                            }


                            if (action.equals("view")) {

                                // decrypt the text and send it
                                BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\ASUS\\Desktop\\SOCKET_2(1)\\Files\\" + fname + ".txt"));
                                String text = br.readLine();
                                br.close();
                                String res2 = AES.encrypt(text, dec1);
                                outstream.writeUTF(res2);

                                //insert user activities information
                                insert_dsa_info(sign_user_name.toString() , sign_password.toString() , dsapublickey.toString() , sign_fname.toString() , sign_action.toString() , null , dtf.format(now));


                            } else if (action.equals("edit")) {

                                int a = auth.intValue();
                                if(a == 1) {
                                    outstream.writeUTF("yes");
                                    // encrypt the response and send it
                                    String res3 = AES.encrypt("ENTER YOUR NEW TEXT FOR UPDATE ", dec1);
                                    outstream.writeUTF(res3);


                                    // receive the new text and encrypt it
                                    String new_text = instream.readUTF();
                                    String decryptedString = AES.decrypt(new_text, dec1);
                                    byte[] sign_text = RSA.decrypt_byte((byte[]) inobj.readObject(), s_privateKey);

//                                    if (DSA.verify(dsapublickey, decryptedString, sign_text)) {
//                                        System.out.println("VERIFY FOR CLIENT NEW TEXT IS OK ");
//                                    } else {
//                                        System.out.println("VERIFY FOR CLIENT NEW TEXT IS NOT OK");
//                                        serverClient.close();
//                                    }


                                    // edit the file
                                    String fileName = "C:\\Users\\ASUS\\Desktop\\SOCKET_2(1)\\Files\\" + fname + ".txt";
                                    try {
                                        Files.delete(Paths.get(fileName));
                                    } catch (IOException e) {
                                        //e.printStackTrace();
                                        System.out.println("...");
                                    }
                                    FileOutputStream updated = new FileOutputStream("C:\\Users\\ASUS\\Desktop\\SOCKET_2(1)\\Files\\" + fname + ".txt");
                                    byte[] b = decryptedString.getBytes();
                                    updated.write(b);
                                    updated.close();

                                    //insert user activities information
                                    insert_dsa_info(sign_user_name.toString() , sign_password.toString() , dsapublickey.toString() , sign_fname.toString() , sign_action.toString() , sign_text.toString() , dtf.format(now));

                                    // encrypt and send the response.
                                    outstream.writeUTF(AES.encrypt("UPDATE DONE", dec1));
                                }else if(a == 0){
                                    outstream.writeUTF("cant edit");
                                    System.out.println("THIS CLIENT CAN'T EDIT ON THE FILE ");
                                }

                            } else {
                                System.out.println("Go out -_-");

                            }
                        } else {


                            String res1 = AES.encrypt("THE FILE NOT EXIST", dec1);
                            outstream.writeUTF(res1);


                            FileWriter create = new FileWriter("C:\\Users\\ASUS\\Desktop\\SOCKET_2(1)\\Files\\" + fname + ".txt");


                            String new_text = instream.readUTF();
                            String decryptedString = AES.decrypt(new_text, dec1);
                            byte[] sign_text = RSA.decrypt_byte((byte[]) inobj.readObject() , s_privateKey);

//                            if(DSA.verify(dsapublickey , decryptedString , sign_text)) {
//                                System.out.println("VERIFY FOR CLIENT NEW TEXT IS OK ");
//                            }else {
//                                System.out.println("VERIFY FOR CLIENT NEW TEXT IS NOT OK");
//                                serverClient.close();
//                            }


                            create.write(decryptedString);
                            create.close();

                            insert_dsa_info(sign_user_name.toString() , sign_password.toString() , dsapublickey.toString() , sign_fname.toString() , "create" , sign_text.toString() , dtf.format(now));

                            outstream.writeUTF(AES.encrypt("THE NEW FILE CREATED", dec1));

                        }

                        reply = instream.readUTF();
                    }



            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            } catch (SQLException e) {
                e.printStackTrace();
            }

            try {
                serverClient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("CONNECTION CLOSED FOR CLIENT_" + client_id);



        }

        public boolean check_user(String username, String password) {
            try {
                //connecting to the database
                Class.forName("com.mysql.jdbc.Driver");
                Connection con = DriverManager.getConnection(
                        "jdbc:mysql://localhost:3306/text_server", "root", "");

                Statement stmt = con.createStatement();
                ResultSet rs = stmt.executeQuery("select user_name,password from server where user_name='" + username + "' and password='" + password + "'");
                System.out.println(username + "   " + password + " ");
                while (rs.next()) {
                    return true;
                }
                con.close();
            } catch (Exception e) {
                System.out.println(e);
            }
            return false;

        }

        public void insert_dsa_info(String user_name , String password , String dsa_public , String file_name , String action , String text , String date) throws ClassNotFoundException, SQLException {

            Class.forName("com.mysql.jdbc.Driver");
            Connection con = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/text_server", "root", "");

            String query = " insert into client_signatured_data (user_name , password , signature , file_name , action , text , date)"
                    + " values (?, ?, ? , ? , ? , ? , ?)";

            PreparedStatement preparedStmt = con.prepareStatement(query);
            preparedStmt.setString(1,user_name);
            preparedStmt.setString(2,password);
            preparedStmt.setString(3,dsa_public);
            preparedStmt.setString(4,file_name);
            preparedStmt.setString(5,action);
            preparedStmt.setString(6,text);
            preparedStmt.setString(7,date);

            preparedStmt.execute();

            con.close();

        }

        public void insert_client(String user_name , String password , String client_publickey ) throws ClassNotFoundException, SQLException {

            Class.forName("com.mysql.jdbc.Driver");
            Connection con = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/text_server", "root", "");

            String query = " insert into server ( user_name , password , c_public_key )"
                    + " values (?, ?, ?)";

            PreparedStatement preparedStmt = con.prepareStatement(query);
            preparedStmt.setString(1,user_name);
            preparedStmt.setString(2,password);
            preparedStmt.setString(3,client_publickey);

            preparedStmt.execute();

            con.close();


        }


        public HashMap<String , String> get_client_data() throws ClassNotFoundException, SQLException {
            Class.forName("com.mysql.jdbc.Driver");
            Connection con = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/text_server", "root", "");
            HashMap<String , String> client = new HashMap<>();
            Statement stmt = con.createStatement();
            ResultSet rs = stmt.executeQuery("select user_name , password from server ");
            while(rs.next()){
                client.put(rs.getString(1) , rs.getString(2));
            }
            con.close();
            return client;
        }

    }


}
