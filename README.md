# Secure_File_Transfer
Authors: Kyle Jolicoeur, Molly E Peterson, Samuel J Toups


The objective of this project is to introduce us to cryptographic tools via the implementation of a secure
file transfer protocol. This program is being created using Python v3.0. 

Completed:
1. Command line interface.
2. MD5 checksum validation to detect hackers who alter the .SFTP_USERS.dat file (buffer overflow, or text editor).
3. Initial user registration.
4. Validation of user credentials before adding data to files (add user, list user).
5. User Login checks for proper credentials.
6. Uses JSON for file storage.
7. Hashes passwords with SHA-256, and compares the hashes to detect correct password used.
8. Password salts were used with the AES hashing algorithm

Not yet complete:
