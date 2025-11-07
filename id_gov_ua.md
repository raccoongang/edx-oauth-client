1 GENERAL DESCRIPTION
Integrated Electronic Identification System (ISEI, id.gov.ua) is a universal platform
designed for:

- electronic identification and authentication of users using electronic signatures (on file, cloud or other secure
  media), Diya.Signature, Diya.OAuth and BankID NBU (user authentication service);
- imposition and verification of electronic signature via the web (signature widget).
  The owner of the system is the state represented by the Ministry of Digital Transformation of Ukraine.
  The owner of the information processed in the ISEI is the system holder.
  The administrator and technical administrator of the ISEI is the state enterprise "DIYA".
  The subjects of interaction are:
- state authorities, local governments, their officials;
- legal entities and individuals - entrepreneurs;
- providers of electronic trust services and providers of electronic identification services;
- administrators of intermediate electronic identification nodes (hubs);
- administrator;
- system holder.
  The objects of interaction are:
- electronic identification means in the context of electronic identification schemes used by
  system users to carry out electronic identification procedures;
- information and communication systems of state authorities, local self-government bodies;
- information and communication systems of legal entities and individual entrepreneurs;
- information and communication systems that implement electronic identification schemes;
- information and communication systems that implement electronic identification schemes within
  cross-border electronic identification.
  The system operates 24 hours a day, seven days a week.
  Access to the system is provided through an open information resource that has an official address on
  the Internet - https://id.gov.ua.

2 INFORMATION PROCESSING PROCEDURE
2.1 General characteristics of the authentication service
Connection to the System user authentication service is carried out for the purpose of electronic
identification and user authentication through identification schemes (electronic signature, Action.Signature,
Action.OAuth, BankID).
During operation, the system interacts with application system servers, users
(clients) of application systems, with electronic identification schemes of Providers, electronic identification schemes
of other electronic identification service providers, including with bank identification servers connected to the
intermediate electronic identification node (hub) Bank ID NBU.
Electronic identification schemes of Providers, electronic identification schemes of other providers of electronic
identification services, including bank identification servers connected to the intermediate electronic identification
node (hub) Bank ID NBU, must comply with the requirements of the legislation on information protection and have permits
in the field of technical and cryptographic information protection, including compliance with the Requirements for
electronic identification means, levels of trust in electronic identification means for their use in the field of
e-government, approved by the order of the Ministry of Digital Transformation of Ukraine dated 05.12.2022 No. 130. The
procedure for interaction of the components of the ISEI during user (client) identification on the application system
server is implemented in accordance with the OAuth 2.0 protocol. To identify application system servers on the ISEI
identification server, the corresponding application systems are pre-registered on the identification server and,
according to the OAuth protocol, the following parameters are set for each application system:
– application system identifier client_id, which uniquely identifies the application system
(the identifier value is given for the test application system registered on the test identification server);
– secret access string client_secret, by which the identification server will issue an access token - access_token to
the application system server;
– public key certificate of the application system key distribution protocol, which is intended for forward encryption
of the received information about the user (client) during transmission between the ISEI identification server and the
application system server.
