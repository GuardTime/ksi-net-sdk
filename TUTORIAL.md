
# KSI .NET SDK Tutorial #

## Disclaimer ##
The SDK is still under development and the following tutorial may not yet describe the final version.

## Prerequisites ##
This tutorial requires at least the basic knowledge of the C# programming language. Current state of the SDK requires
NLog as external library. Also if necessary it is possible to use Bouncy Castle as crypto library instead of Microsoft.
For that Bouncy Castle library is required in addition.

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

## Configuring ##

If you will be signing serveral documents per second then consider setting max allowed http connections in your App.config file. 
Bear in mind that one signing request takes around 1 second.

```xml
  <system.net>
    <connectionManagement>
      <add address="*" maxconnection="100" />
    </connectionManagement>
  </system.net>
```

## KSI ##
The SDK can be used with a simple wrapper KSI, where all functionality is predefined. Following code will cover the both ways.

## Setting up crypto provider ##
First thing we must do is select crypto provider. At the moment there are 2 crypto providers available, Microsoft and
Bouncy Castle. It is also possible to define your own. To set up a crypto provider, following command has to be used.

```cs
    using Guardtime.KSI;

    public class KsiSdkDemo
    {
        public static void Main(string[] args)
        {
            KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());
        }
    }
```

## Data Hashing ##
The signing mechanism does not sign the documents directly but instead signs the calculated imprint of the document.
Imprint is a binary hash value preceded with a single byte for a hash algorithm id. The first example will be simple
program, which hashes a message and outputs it in hex. The hash object will be an input for the actual signing.

```cs
    using Guardtime.KSI;
    using Guardtime.KSI.Hashing;
    using System.Text;
    using System;

    public class KsiSdkDemo
    {
        public static void Main(string[] args)
        {
            KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());
            string data1 = "Hello ";
            string data2 = "world!";

            DataHash documentHash = KsiProvider.CreateDataHasher()
                                               .AddData(Encoding.UTF8.GetBytes(data1))
                                               .AddData(Encoding.UTF8.GetBytes(data2))
                                               .GetHash();

            Console.WriteLine(hash);
        }
    }
```

## Signing the hash ##
In this part it is assumed that document is hashed and DataHash object already exists. Before hash can be signed, it is
required to configure a network client. A network client is an abstraction layer to communicate with the
gateway (or aggregator). It can send signing and extending request and receive responses. It can also download the
publications file. In following tutorial the HTTP client is used (`HttpKsiServiceProtocol`), but there is also TCP 
client available (`TcpKsiServiceProtocol`). 

Result of signing is a KSI signature object. First example is using the simplified wrapper.

```cs
    using Guardtime.KSI;
    using Guardtime.KSI.Hashing;
    using System.Text;
    using Guardtime.KSI.Service;
    using Guardtime.KSI.Publication;
    using Guardtime.KSI.Trust;
    using Guardtime.KSI.Crypto;
    using Guardtime.KSI.Signature;

    public class KsiSdkDemo
    {
        public static void Main(string[] args)
        {
            KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());
            string data1 = "Hello ";
            string data2 = "world!";

            DataHash documentHash = KsiProvider.CreateDataHasher()
                                               .AddData(Encoding.UTF8.GetBytes(data1))
                                               .AddData(Encoding.UTF8.GetBytes(data2))
                                               .GetHash();

            // Create http service protocol which can be used for signing, extending and getting publications file.
            HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signing.service.url",
                "http://extending.service.url", "http://verify.guardtime.com/ksi-publications.bin");

            // Create service settings which are used to access service.
            ServiceCredentials serviceCredentials = new ServiceCredentials("user", "pass");

            // Create trust provider for verifying received publications file.
            IPkiTrustProvider trustProvider = new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                new CertificateSubjectRdnSelector("E=publications@guardtime.com"));

            // Create publications file factory for creating publications file instance.
            PublicationsFileFactory publicationsFileFactory = new PublicationsFileFactory(trustProvider);

            // Create service for signing, getting extended calendar hash chain and verifying and getting publications file.
            KsiService ksiService = new KsiService(httpKsiServiceProtocol, serviceCredentials, httpKsiServiceProtocol,
                serviceCredentials, httpKsiServiceProtocol,
                publicationsFileFactory);

            Ksi ksi = new Ksi(ksiService);
            // Sign hash and retrieve signature.
            IKsiSignature signature = ksi.Sign(documentHash);
        }
    }
```

To sign without simple wrapper is actually even easier. KSI class must be omitted and replaced with following code.

```cs
    IKsiSignature signature = ksiService.Sign(documentHash);
```

## Loading KSI Signature from binary stream ##
Before it is possible to verify or extend the signature, it is necessary to read it to instance. Since usually the signature is stored into database or file, we need to open
stream for given file or database entry. Following example shows how to read the signature from file and create data hash for verification.

```cs
    using Guardtime.KSI;
    using Guardtime.KSI.Signature;
    using System.IO;

    public class KsiSdkDemo
    {
        public static void Main(string[] args)
        {
            KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());

            // Create KSI signature factory.
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();

            IKsiSignature signature;
            DataHash documentHash;

            using (FileStream stream = new FileStream("path-to-signature-file.ksig", FileMode.Open))
            {
                // Create signature from stream.
                signature = signatureFactory.Create(stream);
            }

            using (FileStream stream = new FileStream("path-to-data-file", FileMode.Open))
            {
                // We need to compute the hash from the original data, to make sure it
                // matches the one in the signature and has not been changed.
                // Use the same algorithm as the input hash in the signature.
                documentHash = KsiProvider.CreateDataHasher(signature.InputHash.Algorithm)
                                          .AddData(stream)
                                          .GetHash();
            }
        }
    }
```

## Verifying KSI signature ##
Next logical step would be to verify the signature which was stored somewhere. The simplest way is to use simple wrapper: 
```cs
VerificationResult verificationResult = ksi.Verify(signature, documentHash);

if (verificationResult.ResultCode != VerificationResultCode.Ok)
{
    throw new Exception("Signature verification failed! Error: " + verificationResult.VerificationError);
}
```

Simple wrapper is using default verification policy. 
Verifying using default verification policy without simple wrapper:

```cs
VerificationPolicy policy = new DefaultVerificationPolicy();
VerificationContext context = new VerificationContext(signature)
{
    DocumentHash = documentHash,
    PublicationsFile = ksiService.GetPublicationsFile(),
    KsiService = ksiService,
    IsExtendingAllowed = true
};
VerificationResult verificationResult = policy.Verify(context);
```
There are 4 policies to verify KSI signature.


* Publications based - signature is verified against publications file or user provided publication:

```cs
PublicationBasedVerificationPolicy policy = new PublicationBasedVerificationPolicy();
```

* Key based - signature is verified against PKI signature:

```cs
KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy();
```

* Calendar based - signature is verified against online calendar:
```cs
CalendarBasedVerificationPolicy policy = new CalendarBasedVerificationPolicy();
```

* Default verification policy - at first signature is verified against publications file, if this is not possible then key based verification is done.
  It is a recommended verification policy to be used by default.

```cs
DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
```

Following code represents using default verification policy and will print out the result.

```cs
    using Guardtime.KSI;
    using Guardtime.KSI.Crypto;
    using Guardtime.KSI.Publication;
    using Guardtime.KSI.Service;
    using Guardtime.KSI.Signature;
    using Guardtime.KSI.Signature.Verification;
    using Guardtime.KSI.Signature.Verification.Policy;
    using Guardtime.KSI.Trust;
    using System;
    using System.IO;

    public class KsiSdkDemo
    {
        public static void Main(string[] args)
        {
            KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());

            // Create KSI signature factory.
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();

            IKsiSignature signature;
            DataHash documentHash;

            using (FileStream stream = new FileStream("path-to-signature-file.ksig", FileMode.Open))
            {
                // Create signature from stream.
                signature = signatureFactory.Create(stream);
            }

            using (FileStream stream = new FileStream("path-to-data-file", FileMode.Open))
            {
                // We need to compute the hash from the original data, to make sure it
                // matches the one in the signature and has not been changed.
                // Use the same algorithm as the input hash in the signature.
                documentHash = KsiProvider.CreateDataHasher(signature.InputHash.Algorithm)
                                          .AddData(stream)
                                          .GetHash();
            }

            // Create http service protocol which can be used for signing, extending and getting publications file.
            HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signing.service.url",
                "http://extending.service.url", "http://verify.guardtime.com/ksi-publications.bin");

            // Create service settings which are used to access service.
            ServiceCredentials serviceCredentials = new ServiceCredentials("user", "pass");

            // Create trust provider for verifying received publications file.
            IPkiTrustProvider trustProvider = new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                new CertificateSubjectRdnSelector("E=publications@guardtime.com"));

            // Create publications file factory for creating publications file instance.
            PublicationsFileFactory publicationsFileFactory = new PublicationsFileFactory(trustProvider);

            // Create service for signing, getting extended calendar hash chain and verifying and getting publications file.
            KsiService ksiService = new KsiService(httpKsiServiceProtocol, serviceCredentials, httpKsiServiceProtocol,
                serviceCredentials, httpKsiServiceProtocol, publicationsFileFactory);

            Ksi ksi = new Ksi(ksiService);

            // Verify using default verification policy.
            VerificationResult result = ksi.Verify(signature, documentHash);
            Console.WriteLine(result.ResultCode);
        }
    }
```

To verify the signature without simple wrapper, KSI part should be replaced with following.

```cs
            // Create verification context containing necessary verification info.
            VerificationContext context = new VerificationContext(signature)
            {
                DocumentHash = documentHash,
                KsiService = ksiService,
                PublicationsFile = ksiService.GetPublicationsFile(),
                IsExtendingAllowed = true
            };

            // Verify using default verification policy.
            VerificationResult result = new DefaultVerificationPolicy().Verify(context);
            Console.WriteLine(result.ResultCode);
```

## Extending KSI signature ##

In the following part, the KSI signature is loaded from bytes and extended to closest publication.

```cs
    using Guardtime.KSI;
    using Guardtime.KSI.Crypto;
    using Guardtime.KSI.Publication;
    using Guardtime.KSI.Service;
    using Guardtime.KSI.Signature;
    using Guardtime.KSI.Signature.Verification;
    using Guardtime.KSI.Signature.Verification.Policy;
    using Guardtime.KSI.Trust;
    using System;
    using System.IO;

    public class KsiSdkDemo
    {
        public static void Main(string[] args)
        {
            KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());

            // Create KSI signature factory.
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();

            IKsiSignature signature;
            using (FileStream stream = new FileStream("file path", FileMode.Open))
            {
                signature = signatureFactory.Create(stream);
            }

            // Create http service protocol which can be used for signing, extending and getting publications file.
            HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://signing.service.url",
                "http://extending.service.url", "http://verify.guardtime.com/ksi-publications.bin");

            // Create service settings which are used to access service.
            ServiceCredentials serviceCredentials = new ServiceCredentials("user", "pass");

            // Create trust provider for verifying received publications file.
            IPkiTrustProvider trustProvider = new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                new CertificateSubjectRdnSelector("E=publications@guardtime.com"));

            // Create publications file factory for creating publications file instance.
            PublicationsFileFactory publicationsFileFactory = new PublicationsFileFactory(trustProvider);

            // Create service for signing, getting extended calendar hash chain and verifying and getting publications file.
            KsiService ksiService = new KsiService(httpKsiServiceProtocol, serviceCredentials, httpKsiServiceProtocol,
                serviceCredentials, httpKsiServiceProtocol, publicationsFileFactory);

            Ksi ksi = new Ksi(ksiService);

            // Extend signature to closest publication.
            IKsiSignature extendedSignature = ksi.Extend(signature);
        }
    }
```

Without simple wrapper you should use following code instead.

```cs
    // Get closest publication from publications file.
	PublicationRecordInPublicationFile publicationRecord = ksiService.GetPublicationsFile().GetNearestPublicationRecord(signature.AggregationTime);
    // Get calendar hash chain representing given publication.
    CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime,
        publicationRecord.PublicationData.PublicationTime);

    // Extend signature to publication.
    IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
```

It is also possible to extend to specific publication record from publications file.

```cs
    IKsiSignature extendedSignature = ksi.Extend(signature, publicationRecord);
```

Or publications data object generated from publication string.

```cs
    // Create publication from string.
    PublicationData publicationData =
        new PublicationData("AAAAAA-CWTA3I-AALWDF-55VD5Q-5HEUDE-5BFSXT-HVUZRO-POHGX7-NU5IND-ARFYHR-4JGX6K-GQURVZ");
    IKsiSignature extendedSignature = ksi.Extend(signature, publicationData);
```