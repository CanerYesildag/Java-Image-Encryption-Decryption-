# Java-Image-Encryption-Decryption

In this project, I would like to show how to encrypt and decrypt message between two clients (client_0 and client_1) over server. In addition, client can send encrypted image to server and other client receives this encrypted image and decrypts this image with AES algorithm in CBC mode.
I generated public and private key pair for each client and server. Server signs this public key with server’s private key and we can only decrypt this encrypted client public key with server public key. It provides public key certification for each client.

 Users can post an image to the server class. Owner of an image first generates an AES key and encrypts the image with the AES key in CBC mode in client class. Initialization Vector is generated randomly. Clients also generate a digital signature of the image using his private key and SHA256 hash function. He then encrypts the AES key with the public key of the server. 
	

 
After receiving these, user first extracts the AES key. Next, she decrypts the image. Then, she checks the integrity and authentication of the image by verifying the digital signature. If everything is OK, she displays or stores the image. 

	

	


