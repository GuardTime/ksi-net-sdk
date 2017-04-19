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
Instead of adding references manually you can install packages "ksi-net-sdk" and "ksi-net-sdk-microsoft-crypto" using NuGet package manager.

## Usage ##

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

**Creating ksiService**:

```cs
// Set crypto provider to bouncycastle or microsoft 
KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
//KsiProvider.SetCryptoProvider(new BouncyCastleCryptoProvider()); 

// Create HTTP KSI service protocol
var httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signingservice_url", "http://extendingservice_url", "http://publicationsfile_url");
// Create new KSI service
var ksiService = new KsiService(
    httpKsiServiceProtocol, new ServiceCredentials("sign-user", "pass"),
    httpKsiServiceProtocol, new ServiceCredentials("extend-user", "pass"),
    httpKsiServiceProtocol,
    new PublicationsFileFactory(
        new PkiTrustStoreProvider(
            new X509Store(StoreName.Root), 
            new CertificateSubjectRdnSelector("E=publications@guardtime.com"))));
```

**Creating ksiService and setting PDU version**:

```cs
// Set crypto provider to bouncycastle or microsoft 
KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
//KsiProvider.SetCryptoProvider(new BouncyCastleCryptoProvider()); 

// Create HTTP KSI service protocol
var httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signingservice_url", "http://extendingservice_url", "http://publicationsfile_url");
// Create new KSI service
var ksiService = new KsiService(
    httpKsiServiceProtocol, new ServiceCredentials("sign-user", "pass"),
    httpKsiServiceProtocol, new ServiceCredentials("extend-user", "pass"),
    httpKsiServiceProtocol,
    new PublicationsFileFactory(
        new PkiTrustStoreProvider(
            new X509Store(StoreName.Root), 
            new CertificateSubjectRdnSelector("E=publications@guardtime.com")))
	PduVersion.v1);
```

If PDU version is not given then version v1 is used by default (expected to change to v2 in the future).

If different PDU versions are needed for aggregating and extending then separate KsiServices should be used.

There are 2 ways to use KSI service, with and without simple API wrapper.

**Example using simple wrapper**:

```cs
// Create new simple wrapper
var ksi = new Ksi(ksiService);

// Create new signature by signing given hash
var ksiSignature = ksi.Sign(new DataHash(Base16.Decode("010000000000000000000000000000000000000000000000000000000000000000")));

// Load some older signature and extend it to closest publication
ksiSignature = ksi.Extend(ksiSignature);

// Getting publications file
var publicationsFile = ksi.GetPublicationsFile();
```

**Example without simple wrapper**:

```cs
// Signing 
signature = ksiService.Sign(new DataHash(Base16.Decode("010000000000000000000000000000000000000000000000000000000000000000")));

// Getting publications file 
publicationsFile = ksiService.GetPublicationsFile();

// Extending 
var publicationRecord = publicationsFile.GetNearestPublicationRecord(signature.AggregationTime);
CalendarHashChain calendarHashChain = _ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
var extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
```

The API full reference is available here [http://guardtime.github.io/ksi-net-sdk/](http://guardtime.github.io/ksi-net-sdk/).

## Dependencies ##

| **Dependency**                     | **Version** | **License**                                                        | **Notes**                                                                |
| ---------------------------------- |-------------| -------------------------------------------------------------------|--------------------------------------------------------------------------|
| NLog                               | 2.1         | https://raw.githubusercontent.com/NLog/NLog/master/LICENSE.txt     |                                                                          |
| Bouncy Castle Crypto APIs for .Net | 1.8         | MIT http://www.bouncycastle.org/csharp/licence.html                | Not needed when KSI .NET SDK Microsoft cryptography provider is used     |
| NUnit	                             | 3.0.1       | http://nunit.org/nuget/nunit3-license.txt                          | Required only for testing                                                |

## Compatibility ##

.NET 2.0 or newer

## Contributing ##

See [CONTRIBUTING.md](https://github.com/guardtime/ksi-net-sdk/blob/master/CONTRIBUTING.md) file.

## License ##

See [LICENSE](https://github.com/guardtime/ksi-net-sdk/blob/master/LICENSE) file.