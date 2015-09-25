
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;
using NUnit.Framework;
using System;
using System.IO;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Service
{
    [TestFixture]
    public class HttpAggregationRequestTests
    {
        [Test]
        public void TestHttpAggregationRequest()
        {
            var serviceProtocol = new HttpKsiServiceProtocol(
                "http://ksigw.test.guardtime.com:3333/gt-signingservice",
                "http://ksigw.test.guardtime.com:8010/gt-extendingservice",
                "http://verify.guardtime.com/ksi-publications.bin");


            Console.WriteLine(@"// Creating service");
            var ksiService = new KsiService(serviceProtocol, serviceProtocol, serviceProtocol, new ServiceCredentials("anon", "anon"), new PublicationsFileFactory(), new KsiSignatureFactory());
            Console.WriteLine(@"// Signing hash");
            var createSignatureAsyncResult = ksiService.BeginSign(new DataHash(HashAlgorithm.Sha2256, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }), null, null);
            ksiService.EndSign(createSignatureAsyncResult);

            // TODO: Improve extending
            Console.WriteLine(@"// Extending signature");
            IKsiSignature signature;
            using (var stream = new FileStream("resources/signature/signature-ok.tlv", FileMode.Open))
            {
                signature = new KsiSignatureFactory().Create(stream);
                var extendSignatureAsyncResult = ksiService.BeginExtend(signature.AggregationTime, null, null);
                signature = signature.Extend(ksiService.EndExtend(extendSignatureAsyncResult));
            }
            var pubFileAsyncResult = ksiService.BeginGetPublicationsFile(null, null);
            var extendSignatureAsyncresult = ksiService.BeginExtend(signature.AggregationTime, null, null);
            ksiService.EndExtend(extendSignatureAsyncresult);
            Console.WriteLine(@"// Publications File");
            Console.WriteLine(ksiService.EndGetPublicationsFile(pubFileAsyncResult));
        }
    }
}