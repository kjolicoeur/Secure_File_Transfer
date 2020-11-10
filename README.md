# Secure_File_Transfer
Authors: Kyle Jolicoeur, Molly E Peterson, Samuel J Toups


The objective of this project is to introduce us to cryptographic tools via the implementation of a secure
file transfer protocol. This program is being created using Python v3.0. 

Here is the GitHub link to our code: https://github.com/kjolicoeur/Secure_File_Transfer
Included here is our source code and an image of our output in Jupyter Notebook. In case we commit more before grading, you can look at past
commits, but the image will also stay the same to prove what we had done. We also breakdown below what is currently working and what is not
to hopefully help with determining what we had done at this time.

We are using Jupyter Notebook for easy debugging for now. We will convert this file to be run outside of Jupyter Notebook and from the 
command line for our final submission. 

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
1. We finally got the User Data to output to the JSON file, but we are not yet accessing it to compare login credentials.
   Future logins will not be able to be authenticated since the User Object will be erased. For now this proves that our
   code works, and just needs to be able to pull the data correctly from storage.
2. We just need to encrypt the contact info before storing in the file, which is does not currently do. 

Since the JSON files are incomplete at the moment (missing some security/not being used to pull data), that file is not included here.
We are pretty close to having this all sorted out, so the file may be uploaded to the GitHub soon. 
