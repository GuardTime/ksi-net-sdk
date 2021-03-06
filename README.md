# KSI .NET SDK

Guardtime's KSI Blockchain is an industrial scale blockchain platform that cryptographically ensures data integrity and proves time of existence. The KSI signatures, based on hash chains, link data to this global calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical example is signing of any type of logs - system logs, financial transactions, call records, etc. For more,
see [https://guardtime.com](https://guardtime.com).

The KSI .NET SDK is a software development kit for developers who want to integrate KSI with their .NET based applications
and systems. It provides an API for all KSI functionality, including the core functions - signing of data, extending
and verifying the signatures.

## Installation

In your .NET project add reference to KSI .NET SDK and crypto provider to be used (You can use microsoft or bouncycastle crypto provider).
Instead of adding references manually you can install packages "ksi-net-sdk" and "ksi-net-sdk-microsoft-crypto" using NuGet package manager.

## Usage

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

**Creating ksiService**:

```cs
// Set crypto provider to bouncycastle or microsoft
KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());
//KsiProvider.SetCryptoProvider(new BouncyCastleCryptoProvider());

// Create HTTP KSI service protocol
HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signingservice_url", "http://extendingservice_url", "http://publicationsfile_url");
// Create new KSI service
IKsiService ksiService = new KsiService(
    httpKsiServiceProtocol, new ServiceCredentials("sign-user", "sign-pass"),
    httpKsiServiceProtocol, new ServiceCredentials("extend-user", "extend-pass"),
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
HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signingservice_url", "http://extendingservice_url", "http://publicationsfile_url");
// Create new KSI service
IKsiService ksiService = new KsiService(
    httpKsiServiceProtocol, new ServiceCredentials("sign-user", "sign-pass"),
    httpKsiServiceProtocol, new ServiceCredentials("extend-user", "extend-pass"),
    httpKsiServiceProtocol,
    new PublicationsFileFactory(
        new PkiTrustStoreProvider(
            new X509Store(StoreName.Root),
            new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
    PduVersion.v2);
```

If PDU version is not given then version v2 is used by default.

If different PDU versions are needed for aggregating and extending then separate KsiServices should be used.

**Proxy Configuration**:

To use proxy, add the respective parameters to the `HttpKsiServiceProtocol`, e.g.

```
HttpKsiServiceProtocol httpKsiServiceProtocol =
    new HttpKsiServiceProtocol("http://signingservice_url",
    "http://extendingservice_url",
    "http://publicationsfile_url",
    "http://proxy-url",
    new NetworkCredential("proxy-user", "proxy-pass"));
```


There are 2 ways to use KSI service, with and without simple API wrapper.

**Example using simple wrapper**:

```cs
// Create new simple wrapper
Ksi ksi = new Ksi(ksiService);

// Create new signature by signing document hash
byte[] documentBytes = new byte[] { 1, 2, 3 };
DataHash documentHash = KsiProvider.CreateDataHasher()
                                    .AddData(documentBytes)
                                    .GetHash();
IKsiSignature signature = ksi.Sign(documentHash);

// Extend an older signature to the closest publication
IKsiSignature extendedSignature = ksi.Extend(signature);

// Verify signature
VerificationResult verificationResult = ksi.Verify(signature, documentHash);
if (verificationResult.ResultCode != VerificationResultCode.Ok)
{
    throw new Exception("Signature verification failed! Error: " + verificationResult.VerificationError);
}
```

**Example without simple wrapper**:

```cs
// Create new signature by signing document hash
byte[] documentBytes = new byte[] { 1, 2, 3 };
DataHash documentHash = KsiProvider.CreateDataHasher()
                                    .AddData(documentBytes)
                                    .GetHash();
IKsiSignature signature = ksiService.Sign(documentHash);

// Getting publications file
IPublicationsFile publicationsFile = ksiService.GetPublicationsFile();

// Extend an older signature to the closest publication
PublicationRecordInPublicationFile publicationRecord = publicationsFile.GetNearestPublicationRecord(signature.AggregationTime);
if (publicationRecord == null)
{
    throw new Exception("No suitable publication yet.");
}
CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);

// Verify signature
VerificationResult verificationResult = new DefaultVerificationPolicy().Verify(signature, documentHash, ksiService);
if (verificationResult.ResultCode != VerificationResultCode.Ok)
{
    throw new Exception("Signature verification failed! Error: " + verificationResult.VerificationError);
}
```

More detailed tutorial is available here [TUTORIAL.md](https://github.com/guardtime/ksi-net-sdk/blob/master/TUTORIAL.md).

The API full reference is available here [http://guardtime.github.io/ksi-net-sdk/](http://guardtime.github.io/ksi-net-sdk/).

## Dependencies

| **Dependency**                     | **Version** | **License**                                                        | **Notes**                                                                |
| ---------------------------------- |-------------| -------------------------------------------------------------------|--------------------------------------------------------------------------|
| NLog                               | 2.1         | https://raw.githubusercontent.com/NLog/NLog/master/LICENSE.txt     |                                                                          |
| Bouncy Castle Crypto APIs for .Net | 1.8         | MIT http://www.bouncycastle.org/csharp/licence.html                | Not needed when KSI .NET SDK Microsoft cryptography provider is used     |
| NUnit	                             | 3.0.1       | http://nunit.org/nuget/nunit3-license.txt                          | Required only for testing                                                |

## Compatibility

.NET 2.0 or newer

## Contributing

See [CONTRIBUTING.md](https://github.com/guardtime/ksi-net-sdk/blob/master/CONTRIBUTING.md) file.

## License

See [LICENSE](https://github.com/guardtime/ksi-net-sdk/blob/master/LICENSE) file.
