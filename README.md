# KSI .NET SDK #
Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically 
ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global 
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term 
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical 
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, 
see [https://guardtime.com](https://guardtime.com).

The KSI .NET SDK is a software development kit for developers who want to integrate KSI with their .NET based applications 
and systems. It provides an API for all KSI functionality, including the core functions - signing of data, extending 
and verifying the signatures.

## Installation ##

In your .NET project add reference to KSI .NET SDK and crypto provider to be used (You can use microsoft or bouncycastle crypto provider).

## Usage ##

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

A simple usage example:

```java
// Set crypto provider to bouncycastle or microsoft 
KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
//KsiProvider.SetCryptoProvider(new BouncyCastleCryptoProvider()); 

// Create HTTP KSI service protocol
var httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signingservice_url", "http://extendingservice_url", "http://publicationsfile_url");
// Create new KSI service
var ksiService = new KsiService(httpKsiServiceProtocol, httpKsiServiceProtocol, httpKsiServiceProtocol, new ServiceCredentials("anon", "anon"), new PublicationsFileFactory(new PkiTrustStoreProvider()), new KsiSignatureFactory());

// Create new simple wrapper
var ksi = new Ksi(ksiService);

// Create new signature by signing given hash
var ksiSignature = ksi.Sign(new DataHash(Base16.Decode("010000000000000000000000000000000000000000000000000000000000000000")));

// Load some older signature and to extend it to head use following command
ksiSignature = ksi.ExtendToHead(ksiSignature);

// For getting publications file
var publicationsFile = ksi.GetPublicationsFile();


// Signing without simple wrapper
signature = ksiService.Sign(new DataHash(Base16.Decode("010000000000000000000000000000000000000000000000000000000000000000")));

// Getting publications file without simple wrapper
publicationsFile = _ksiService.GetPublicationsFile();

// Extending without simple wrapper
var publicationRecord = publicationsFile.GetLatestPublication();
CalendarHashChain calendarHashChain = _ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
var extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
```
The API full reference is available here [http://guardtime.github.io/ksi-net-sdk/](http://guardtime.github.io/ksi-net-sdk/).

## License ##

See LICENSE file.