# Hybrid-SHA
A Hybrid Hashing Security Algorithm using RMI

**Sender Side (Client):**
1. Generate the public key using a symmetric algorithm (AES).
2. Using an asymmetric algorithm (RSA) to generate the secret key.
3. Generate the Signature (message digest of  secret key).
4. Encrypt the message using public key (STEP 1).
5. Send the encrypted message and signature (STEP 3) to the recipient.

**Recipient Side (Server):**
Verify the Signature (message digest) and decrypt the message
1. Calculate the message digest following the same STEP 1,2 & 3 of Sender Side.
2. Compare the calculated message digest and received message digest.
3. If both message digest are matching . then the signature is valid and then you can decrypt the encrypted message.

**Instruction:**
If you are using cli or shell then remove the package name from the program and then execute the program.
1. First compile the HybridSHA_SERVER.java file and then run the associated class file

   `javac HybridSHA_SERVER.java`
   
   `java HybridSHA_SERVER`
   
2. Second compile the Hybrid_CLIENT.java file and then run the associated class file

   `java HybridSHA_CLIENT.java`
   
   `java HybridSHA_CLIENT`

# Screenshots:

**CLIENT**

![3](https://user-images.githubusercontent.com/25420334/117573894-24295a80-b0f8-11eb-81d8-b26d6dc563e0.png)

**SERVER**

![4](https://user-images.githubusercontent.com/25420334/117573943-5cc93400-b0f8-11eb-99ce-97dcb4144f5a.png)

# References:
1. AbdElnapi, Noha MM, Fatma A. Omara, and Nahla F. Omran. "A hybrid hashing security algorithm for data storage on cloud computing." International Journal of Computer Science and Information Security (IJCSIS) 14.4 (2016).

# Video Demonstration

[![Demonstration](https://img.youtube.com/vi/SX5mSCy0lWo.maxresdefault.jpg)](https://www.youtube.com/watch?v=SX5mSCy0lWo)
