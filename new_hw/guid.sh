# Generate private key
openssl genpkey -algorithm Ed25519 -out server_priv.pem
openssl genpkey -algorithm Ed25519 -out client_priv.pem


# Extract public key
openssl pkey -in server_priv.pem -pubout -out server_pub.pem
openssl pkey -in client_priv.pem -pubout -out client_pub.pem

# compilation
gcc   server.c -o server  -lssl -lcrypto
gcc   client.c -o client  -lssl -lcrypto


# run
./server   ------ first  this one 
 ./client