# jwt-demo
This is example JWT with Spring Security 

based on YouTube Video Spring Boot Rest API Json Web Tokens: 
https://www.youtube.com/watch?v=KYNR5js2cXE

Auth UserService Layout:
https://github.com/Yoh0xFF/java-spring-security-example

blacklist JWT:
https://github.com/GaetanoPiazzolla/blacklisting-jwt

additional Resource for Custom Database User Validation


* Openssl is needed, can use from Git Bash install *

add to path:
C:\Program Files\Git\usr\bin

-commands to create RSA

1.Create Key pair: 
openssl genrsa -out keypair.pem 2048 

2.Create Public Key: 
openssl rsa -in keypair.pem -pubout -out public.pem

3.Create Private Key: 
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem
