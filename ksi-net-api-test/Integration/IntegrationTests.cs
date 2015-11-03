using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Integration
{
    public class IntegrationTests
    {


        private static readonly HttpKsiServiceProtocol ksiServiceProtocol =
            new HttpKsiServiceProtocol("http://ksigw.test.guardtime.com:3333/gt-signingservice", "http://ksigw.test.guardtime.com:8010/gt-extendingservice", "http://verify.guardtime.com/ksi-publications.bin");

        private static object[] TestCases =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        ksiServiceProtocol,
                        ksiServiceProtocol,
                        ksiServiceProtocol,
                        new ServiceCredentials("anon", "anon"),
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider()),
                        new KsiSignatureFactory()))
            }
        };
    }
}