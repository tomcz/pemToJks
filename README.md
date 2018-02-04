[![Build Status](https://travis-ci.org/tomcz/pemToJks.svg?branch=master)](https://travis-ci.org/tomcz/pemToJks)

# PEM to JKS

This is a Kotlin command line application that adds PEM-encoded certificates (in X.509 format)
and RSA private keys (in PKCS #8 format) to a Java KeyStore, so that they can be used for
SSL/TLS in Java applications.

## Development

### Requirements

1. Java 8
2. Clone this project

### Build the application

Run the following from the root of the project:

```
./gradlew
```

This creates a `build/distributions/pemToJks.zip` application bundle.

## Run the application

The following example commands are run from the root of the unzipped application bundle.

View help text:

```
$> ./bin/pemToJks -h
usage: pemToJks
 -alias <arg>     Java keystore alias for certificate/key
 -aliaspw <arg>   Java keystore key alias password
 -cert <arg>      Path to PEM certificate file
 -h,--help        Print this message and exit
 -key <arg>       Path to PEM key file
 -store <arg>     Path to java keystore file
 -storepw <arg>   Java keystore password
```

Add a trusted certificate to a keystore:  
NOTE: If the keystore does not exist, it will be created.

```
$> ./bin/pemToJks -cert cert.pem -alias trustme -store test.jks
Reading certificate file
Loading keystore
Adding certificate entry to keystore
Saving keystore
Done
```

Add a certificate chain and private key to a keystore:  
NOTE: If the keystore does not exist, it will be created.

```
$> ./bin/pemToJks -cert cert.pem -key key.pem -alias useme -store test.jks 
Reading certificate file
Reading key file
Verifying certificate against key
Loading keystore
Adding key & cert chain entry to keystore
Saving keystore
Done
```
