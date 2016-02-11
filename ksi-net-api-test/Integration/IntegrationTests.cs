using System.Net;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Integration
{
    public class IntegrationTests
    {
        private static readonly HttpKsiServiceProtocol HttpKsiServiceProtocol =
            new HttpKsiServiceProtocol("http://ksigw.test.guardtime.com:3333/gt-signingservice", "http://ksigw.test.guardtime.com:8010/gt-extendingservice",
                "http://verify.guardtime.com/ksi-publications.bin", 100000);

        //private static readonly HttpKsiServiceProtocol HttpKsiServiceProtocol =
        //    new HttpKsiServiceProtocol("http://ksigw.test.guardtime.com:3333/gt-signingservice", "http://ksigw.test.guardtime.com:8010/gt-extendingservice",
        //        "http://verify.guardtime.com/ksi-publications.bin", 100000, "http://127.0.0.1:8888", new NetworkCredential("1a", "1"));

        private static readonly HttpKsiServiceProtocol HttpKsiServiceProtocolInvalidUrls =
            new HttpKsiServiceProtocol("http://ksigw.test.guardtime.comx:3333/gt-signingservice", "http://ksigw.test.guardtime.comx:8010/gt-extendingservice",
                "http://verify.guardtime.comx/ksi-publications.bin", 100000);

        private static readonly TcpKsiServiceProtocol TcpKsiServiceProtocol = new TcpKsiServiceProtocol("ksigw.test.guardtime.com", 3332, 100000);

        private static readonly TcpKsiServiceProtocol TcpKsiServiceProtocolInvalidUrl = new TcpKsiServiceProtocol("ksigw.test.guardtime.comx", 3332, 100000);

        private static readonly TcpKsiServiceProtocol TcpKsiServiceProtocolInvalidPort = new TcpKsiServiceProtocol("ksigw.test.guardtime.com", 1234, 100000);

        protected static object[] HttpTestCases =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        HttpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        new ServiceCredentials("anon", "anon"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        protected static object[] HttpTestCasesInvalidPass =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        HttpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        new ServiceCredentials("anon", "anonx"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        protected static object[] HttpTestCasesInvalidUrl =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        HttpKsiServiceProtocolInvalidUrls,
                        HttpKsiServiceProtocolInvalidUrls,
                        HttpKsiServiceProtocolInvalidUrls,
                        new ServiceCredentials("anon", "anon"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        protected static object[] TcpTestCases =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        TcpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        new ServiceCredentials("anon", "anon"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        protected static object[] TcpTestCasesInvalidPass =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        TcpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        HttpKsiServiceProtocol,
                        new ServiceCredentials("anon", "anonx"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        protected static object[] TcpTestCasesInvalidUrl =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        TcpKsiServiceProtocolInvalidUrl,
                        HttpKsiServiceProtocolInvalidUrls,
                        HttpKsiServiceProtocolInvalidUrls,
                        new ServiceCredentials("anon", "anon"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        protected static object[] TcpTestCasesInvalidPort =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        TcpKsiServiceProtocolInvalidPort,
                        HttpKsiServiceProtocolInvalidUrls,
                        HttpKsiServiceProtocolInvalidUrls,
                        new ServiceCredentials("anon", "anon"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void GetPublicationsFileTest(Ksi ksi)
        {
            IPublicationsFile publicationsFile = ksi.GetPublicationsFile();

            PublicationRecordInPublicationFile latest = publicationsFile.GetLatestPublication();
            if (latest == null)
            {
                Assert.True(true);
                return;
            }

            PublicationRecordInPublicationFile prev = publicationsFile.GetNearestPublicationRecord(latest.PublicationData.PublicationTime - 35 * 24 * 3600);

            if (prev == null)
            {
                Assert.True(true);
                return;
            }

            Assert.True(latest.PublicationData.PublicationTime > prev.PublicationData.PublicationTime, "Signature should verify with key based policy");
        }
    }
}