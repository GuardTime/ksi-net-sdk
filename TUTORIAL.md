
# KSI .NET SDK Tutorial #

## Disclaimer ##
The SDK is still under development and the following tutorial may not yet describe the final version.

## Prerequisites ##
This tutorial requires at least the basic knowledge of the C# programming language. Current state of the SDK requires
NLog as external library. Also if necessary it is possible to use Bouncy Castle as crypto library instead of Microsoft.
For that Bouncy Castle library is required in addition.

## KSI ##
The SDK can be used with a simple wrapper KSI, where all functionality is predefined. Following code will cover the both ways.

## Setting up crypto provider ##
First thing we must do is select crypto provider. At the moment there are 2 crypto providers available, Microsoft and
Bouncy Castle. Also it is possible to define your own. To set up a crypto provider, following command has to be used.

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
            string data2 = "nerd!";

            IDataHasher hasher = new DataHasher();
            hasher.AddData(Encoding.UTF8.GetBytes(data1));
            hasher.AddData(Encoding.UTF8.GetBytes(data2));

            DataHash hash = hasher.GetHash();
            Console.WriteLine(hash);
        }
    }
```

## Signing the hash ##
In this part it is assumed that document is hashed and DataHash object already exists. Before hash can be signed, it is
required to configure the network client. A network client is an abstraction layer to communicate with the
gateway (or aggregator). It can send signing and extending request and receive responses. Also it can download the
publications file. In following tutorial the HTTP client is used. Result is KSI signature object. First example is using the
simplified wrapper.

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
            string data2 = "nerd!";

            IDataHasher hasher = new DataHasher();
            hasher.AddData(Encoding.UTF8.GetBytes(data1));
            hasher.AddData(Encoding.UTF8.GetBytes(data2));

            DataHash hash = hasher.GetHash();

            // Creates http service protocol which can be used for signing, extending and getting publications file.
            HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://192.168.11.123",
                "http://192.168.11.123:8081", "http://verify.guardtime.com/ksi-publications.bin");

            // Creates service settings which are used to access service.
            ServiceCredentials serviceCredentials = new ServiceCredentials("anon", "anon");

            // Windows uses always its own trust store by default, so adding it is not required.
            IPkiTrustProvider trustProvider = new PkiTrustStoreProvider(null,
                new CertificateSubjectRdnSelector("E=publications@guardtime.com"));

            // Create publications file factory.
            PublicationsFileFactory publicationsFileFactory = new PublicationsFileFactory(trustProvider);

            // Create KSI signature factory.
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();

            // Create service for signing, getting extended calendar hash chain and verifying and getting publications file.
            KsiService ksiService = new KsiService(httpKsiServiceProtocol, serviceCredentials, httpKsiServiceProtocol,
                serviceCredentials, httpKsiServiceProtocol,
                publicationsFileFactory, signatureFactory);

            Ksi ksi = new Ksi(ksiService);
            // Sign hash and retrieve signature.
            IKsiSignature signature = ksi.Sign(hash);
        }
    }
```

To sign without simple wrapper is actually even easier. KSI class must be omitted and replaced with following code.

```cs
    IKsiSignature signature = ksiService.Sign(hash);
```

## Loading KSI Signature from binary stream ##
Before it is possible to verify or extend the signature, it is necessary to read it to instance. Since usually the signature is stored into database or file, we need to open
stream for given file or database entry. Following example shows how to read the signature from file.

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
            using (FileStream stream = new FileStream("file path", FileMode.Open))
            {
                // Create signature from stream.
                signature = signatureFactory.Create(stream);
            }
        }
    }
```

## Verifying KSI signature ##
Next logical step would be to verify the signature which was stored somewhere. There are 4 policies to verify the signature.
* Calendar based - signature is verified against online calendar
 * Usage for policy:

```cs
		CalendarBasedVerificationPolicy policy = new CalendarBasedVerificationPolicy();
```

* Key based - signature is verified against PKI signature
 * Usage for policy: for bouncycastle full truststore has to be included in parameter, for windows built-in trust store is used

```cs
        KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(), 
            new CertificateSubjectRdnSelector("E=publications@guardtime.com"));
```

* Publications based - signature is verified against publications file or user provided publication
 * Usage for policy:

```cs
        PublicationBasedVerificationPolicy policy = new PublicationBasedVerificationPolicy();
```

Following code represents the verification against publications file and will print out the result.

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

            // Creates http service protocol which can be used for signing, extending and getting publications file.
            HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://192.168.11.123",
                "http://192.168.11.123:8081", "http://verify.guardtime.com/ksi-publications.bin");

            // Creates service settings which are used to access service.
            ServiceCredentials serviceCredentials = new ServiceCredentials("anon", "anon");

            // Windows uses always its own trust store by default, so adding it is not required.
            IPkiTrustProvider trustProvider = new PkiTrustStoreProvider(null,
                new CertificateSubjectRdnSelector("E=publications@guardtime.com"));

            // Create publications file factory.
            PublicationsFileFactory publicationsFileFactory = new PublicationsFileFactory(trustProvider);

            // Create service for signing, getting extended calendar hash chain and verifying and getting publications file.
            KsiService ksiService = new KsiService(httpKsiServiceProtocol, serviceCredentials, httpKsiServiceProtocol,
                serviceCredentials, httpKsiServiceProtocol, publicationsFileFactory, signatureFactory);

            Ksi ksi = new Ksi(ksiService);

            // Create verification context for necessary verification info.
            VerificationContext context = new VerificationContext(signature);
            context.KsiService = ksiService;
            context.PublicationsFile = ksi.GetPublicationsFile();

            // Verify against publication based verification policy.
            VerificationResult result = ksi.Verify(context, new PublicationBasedVerificationPolicy());
            Console.WriteLine(result.ResultCode);
        }
    }
```

To verify the signature without simple wrapper, KSI part should be replaced with following.

```cs
    VerificationResult result = new PublicationBasedVerificationPolicy().Verify(context);
```

## Extending KSI signature ##

In following part, the KSI signature is loaded from bytes. Then it is verified like it was done in previous chapter and after that 
it is extended to closest publication.

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

            // Creates http service protocol which can be used for signing, extending and getting publications file.
            HttpKsiServiceProtocol httpKsiServiceProtocol = new HttpKsiServiceProtocol("http://192.168.11.123",
                "http://192.168.11.123:8081", "http://verify.guardtime.com/ksi-publications.bin");

            // Creates service settings which are used to access service.
            ServiceCredentials serviceCredentials = new ServiceCredentials("anon", "anon");

            // Windows uses always its own trust store by default, so adding it is not required.
            IPkiTrustProvider trustProvider = new PkiTrustStoreProvider(null,
                new CertificateSubjectRdnSelector("E=publications@guardtime.com"));

            // Create publications file factory.
            PublicationsFileFactory publicationsFileFactory = new PublicationsFileFactory(trustProvider);

            // Create service for signing, getting extended calendar hash chain and verifying and getting publications file.
            KsiService ksiService = new KsiService(httpKsiServiceProtocol, serviceCredentials, httpKsiServiceProtocol,
                serviceCredentials, httpKsiServiceProtocol, publicationsFileFactory, signatureFactory);

            Ksi ksi = new Ksi(ksiService);

            // Extend signature to closest publication.
            IKsiSignature extendedSignature = ksi.Extend(signature);
        }
    }
```

Without simple wrapper you should use following commands instead of it.

```cs
    // Get closest publication from publications file.
	PublicationRecordInPublicationFile publicationRecord = ksiService.GetPublicationsFile().GetNearestPublicationRecord(signature.AggregationTime);
    // Get calendar hash chain representing given publication.
    CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime,
        publicationRecord.PublicationData.PublicationTime);

    // Extend signature to publication.
    IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
```

Also its possible to extend to specific publication record from publications file.

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