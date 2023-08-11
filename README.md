# Functional JWT API for User Login
This is example JWT project with Spring Security. Handles Registration, Login, Logout, Refresh Token, expired JWT and Refresh Tokens

based on YouTube Video Spring Boot Rest API Json Web Tokens: 
https://www.youtube.com/watch?v=KYNR5js2cXE

Auth UserService Layout:
https://github.com/Yoh0xFF/java-spring-security-example

blacklist JWT:
https://github.com/GaetanoPiazzolla/blacklisting-jwt

Solution to Roles: https://dev.to/toojannarong/spring-security-with-jwt-the-easiest-way-2i43

Info on filtering: https://medium.com/@akhileshanand/spring-boot-api-security-with-jwt-and-role-based-authorization-fea1fd7c9e32

Creating Refresh Token: https://www.bezkoder.com/spring-security-refresh-token/

Controller Advice: https://www.bezkoder.com/spring-boot-restcontrolleradvice/

***************** OLD references ***********


Additional JWT Role Resources:
https://medium.com/@akhileshanand/spring-boot-api-security-with-jwt-and-role-based-authorization-fea1fd7c9e32
Roles:https://stackoverflow.com/questions/58205510/spring-security-mapping-oauth2-claims-with-roles-to-secure-resource-server-endp


***********


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
