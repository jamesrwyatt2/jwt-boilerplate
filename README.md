# jwt-demo
This is example JWT with Spring Secuirty 


-openssl from Git Bash
add to path:
C:\Program Files\Git\usr\bin

-commands to create RSA
1.Create Key pair
openssl genrsa -out keypair.pem 2048 
2.Create Public Key
openssl rsa -in keypair.pem -pubout -out public.pem
3.Create Private Key
