JWKS Server

Overview

This project implements a basic JWKS (JSON Web Key Set) Server that provides public keys for verifying JSON Web Tokens (JWTs). The server has the following functionalities:

•	Key Generation: Generates RSA key pairs, each associated with a Key ID (kid) and an expiry timestamp.

•	JWT Authentication: Issues signed JWTs upon successful authentication via the /auth endpoint.

•	JWKS Endpoint: Serves the public keys via a RESTful endpoint at /jwks.

•	Key Expiry Handling: Only serves non-expired keys and allows issuing JWTs with expired keys using the expired query parameter.


This project is designed to simulate authentication and JWT handling for educational purposes.
________________________________________
Features

•	Key Generation: Generates RSA key pairs with unique kid values and expiry timestamps.

•	JWT Signing: Issues signed JWTs for authenticated requests.

•	JWKS Endpoint: A /jwks endpoint that serves the public keys in the JWKS format.

•	Key Expiry Handling: Expired keys are not included in the JWKS response, but you can request expired JWTs via the /auth endpoint with the expired=true query parameter.

•	Authentication: A simple mock authentication system is implemented for the /auth endpoint.
________________________________________
Steps to Run the Server

1.	Clone the Repository

2.	Install Dependencies

3.	Generate RSA Key Pairs

4.	Run the Server
________________________________________
Running Tests
Test Suite
The project includes a set of automated tests to ensure the functionality works as expected. The tests check various aspects like key expiry, JWT validity, and proper API responses.
1.	Install Testing Dependencies
2.	Run the Tests
3.	Test Coverage
