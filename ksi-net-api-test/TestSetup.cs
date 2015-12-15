using NUnit.Framework;

namespace Guardtime.KSI
{
    [SetUpFixture]
    public class TestSetup
    {
        [SetUp]
        public void RunBeforeAnyTests()
        {
            //KsiProvider.SetCryptoProvider(new BouncyCastleCryptoProvider());
            KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider());
        }
    }
}