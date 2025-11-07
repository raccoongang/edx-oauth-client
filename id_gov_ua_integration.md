# Integration with Id.gov.ua Identity Provider

## Overview

This document describes the integration between the examination system (Open EDX) and the State Certificate Registry (RDS) with the external Identity provider Id.gov.ua. This integration enables secure authentication and user identification through the Ukrainian government's official electronic identification system.

Id.gov.ua (Integrated Electronic Identification System or ISEI) is a universal platform designed for electronic identification and authentication of users using various methods including electronic signatures, Diya.Signature, Diya.OAuth, and BankID NBU. It is owned by the Ministry of Digital Transformation of Ukraine and administered by the state enterprise "DIYA".

The integration with Id.gov.ua is the only external system integration that occurs in both the Open EDX Examination System and the State Certificate Registry. Neither system has its own registration process - all user authentication is handled through Id.gov.ua.

## Architecture

The integration architecture consists of several key components that work together to provide secure authentication:

1. **Open EDX Third-Party Authentication Framework**: The standard Open EDX component for integrating external authentication providers
2. **Custom OAuth Backend**: A specialized backend for the Id.gov.ua provider
3. **Directed Encryption Module**: A security component that handles the encryption and decryption of sensitive user data

```
┌─────────────────┐                      ┌─────────────────┐
│                 │                      │                 │
│    Open EDX     │                      │    Id.gov.ua    │
│       or        │◄────── OAuth2 ───────┤  Identity       │
│      RDS        │      Protocol        │  Provider       │
│                 │                      │                 │
└────────┬────────┘                      └────────┬────────┘
         │                                        │
         │                                        │
         │                                        │
┌────────▼────────┐                      ┌────────▼────────┐
│                 │                      │                 │
│  Custom OAuth   │                      │   Encrypted     │
│    Backend      │◄───── Encrypted ─────┤   User Data     │
│                 │      User Data       │                 │
└────────┬────────┘                      └─────────────────┘
         │
         │
         │
┌────────▼────────┐
│                 │
│  IIT Protection │
│     Module      │
│  (Decryption)   │
│                 │
└────────┬────────┘
         │
         │
         │
┌────────▼────────┐
│                 │
│  User Creation  │
│  or Login       │
│                 │
└─────────────────┘
```

### Authentication Flow

The authentication process follows these steps:

1. User initiates login through the Id.gov.ua option on the Open EDX or RDS login page
2. The system redirects the user to the Id.gov.ua authentication service
3. User authenticates using one of the available methods (e.g., BankID, electronic signature)
4. Id.gov.ua validates the user's identity and sends encrypted user information back to the system
5. The system decrypts the user information using the directed encryption module
6. If the user doesn't exist, a new account is created with the information provided by Id.gov.ua
7. The user is logged in and redirected to the appropriate page

## Components

### 1. Third-Party Authentication Configuration

The Open EDX platform uses the `third_party_auth` Django application to configure and manage authentication with external providers. For Id.gov.ua, this involves setting up an OAuth2 provider configuration with specific parameters:

- **Provider Name**: Id.gov.ua
- **Backend Class**: The custom backend class for Id.gov.ua
- **Client ID**: Provided by Id.gov.ua during registration
- **Client Secret**: Provided by Id.gov.ua during registration
- **Authorization URL**: The Id.gov.ua authorization endpoint
- **Access Token URL**: The Id.gov.ua token endpoint
- **User Data URL**: The Id.gov.ua user data endpoint

The configuration is stored in the database using the `OAuth2ProviderConfig` model, which allows administrators to enable/disable the provider and modify its settings through the Django admin interface.

### 2. Custom OAuth Backend

The custom OAuth backend for Id.gov.ua is implemented in the `edx-oauth-client` package. The main components include:

- **GenericOAuthBackend Class**: Extends the `BaseOAuth2` class from python-social-auth to handle the specific requirements of Id.gov.ua
- **Custom Authentication Pipeline**: A series of functions that process the authentication data and create or update user accounts

Key features of the backend:

- Handles the OAuth2 authentication flow with Id.gov.ua
- Processes the encrypted user information received from Id.gov.ua
- Maps Id.gov.ua user attributes to Open EDX user fields
- Stores the user's DRFO code (Ukrainian tax ID) in the user profile metadata
- Sets Ukrainian as the default language for new users

### 3. Directed Encryption Module

The `iit-protection` package implements the security mechanisms required for secure communication with Id.gov.ua. It provides a wrapper around the EUSignCP library, which is the official cryptographic library for Ukrainian electronic signatures and encryption.

Key features:

- **Certificate Management**: Handles the certificates used for encryption and digital signatures
- **Directed Encryption**: Implements the encryption and decryption of user data using DSTU-4145 algorithms (Ukrainian national cryptographic standard)
- **Digital Signatures**: Provides functionality for verifying digital signatures

The most critical function is `develop_data()`, which decrypts the encrypted user information received from Id.gov.ua during the authentication process.

## Security Considerations

The integration with Id.gov.ua provides several security benefits:

1. **Government-Verified Identity**: Users are authenticated through official government channels, ensuring their identity is verified
2. **Directed Encryption**: Sensitive user data is encrypted during transmission using strong cryptographic algorithms
3. **No Password Storage**: The systems do not store user passwords, eliminating the risk of password breaches
4. **Compliance with Ukrainian Regulations**: The integration follows the requirements for electronic identification means as approved by the Ministry of Digital Transformation of Ukraine

## Implementation Details

### Configuration Requirements

To enable the Id.gov.ua integration, the following settings must be configured:

1. **OAuth2 Provider Configuration**:
   - Register the application with Id.gov.ua to obtain Client ID and Client Secret
   - Configure the OAuth2ProviderConfig in the Django admin

2. **Cryptographic Settings**:
   - Install the EUSignCP library
   - Configure the certificate and key files in the Django settings:
     - `CAS`: Path to the CAs.json file
     - `CA_CERTIFICATES`: Path to the CACertificates.p7b file
     - `PKEY_FILE`: Path to the private key file
     - `PKEY_PASSWORD`: Password for the private key
     - `PKEY_CERTS_FILES`: List of certificate files
     - `PKEY_ISSUER_CN`: Issuer common name

### User Data Mapping

The following user data is received from Id.gov.ua and mapped to the Open EDX user model:

- **Email**: Used as the username and email address
- **Name**: Combination of last name, first name, and middle name
- **DRFO Code**: Stored in the user profile metadata
- **Country**: Set to "UA" by default

### Error Handling

The integration includes error handling for various scenarios:

- Missing email address: If Id.gov.ua doesn't provide an email, the user is prompted to enter one
- Authentication failures: Appropriate error messages are displayed to the user
- Decryption failures: Logged for troubleshooting

## Conclusion

The integration with Id.gov.ua provides a secure and reliable authentication mechanism for both the Open EDX Examination System and the State Certificate Registry. By leveraging the Ukrainian government's official electronic identification system, it ensures that users are properly identified and authenticated, which is critical for the examination and certification processes.

The use of directed encryption and compliance with Ukrainian cryptographic standards ensures that sensitive user data is protected during transmission, maintaining the security and integrity of the authentication process.