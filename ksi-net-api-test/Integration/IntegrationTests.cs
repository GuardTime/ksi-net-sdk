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
        private static readonly HttpKsiServiceProtocol KsiServiceProtocol =
            new HttpKsiServiceProtocol("http://ksigw.test.guardtime.com:3333/gt-signingservice", "http://ksigw.test.guardtime.com:8010/gt-extendingservice",
                "http://verify.guardtime.com/ksi-publications.bin");

        protected static object[] TestCases =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        KsiServiceProtocol,
                        KsiServiceProtocol,
                        KsiServiceProtocol,
                        new ServiceCredentials("anon", "anon"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(TrustStoreUtilities.GetTrustAnchorCollection(), new CertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        new KsiSignatureFactory()))
            }
        };

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TestCases))]
        public void GetPublicationsFileTest(Ksi ksi)
        {
            IPublicationsFile publicationsFile = ksi.GetPublicationsFile();

            PublicationRecord latest = publicationsFile.GetLatestPublication();
            if (latest == null)
            {
                Assert.True(true);
                return;
            }

            PublicationRecord prev = publicationsFile.GetNearestPublicationRecord(latest.PublicationData.PublicationTime - 35 * 24 * 3600);

            if (prev == null)
            {
                Assert.True(true);
                return;
            }

            Assert.True(latest.PublicationData.PublicationTime > prev.PublicationData.PublicationTime, "Signature should verify with key based policy");
        }
    }
}