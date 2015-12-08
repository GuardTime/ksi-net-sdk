using Guardtime.KSI.Mono;
using NUnit.Framework;

namespace Guardtime.KSI
{
    [SetUpFixture]
    public class TestSetup
    {
        [SetUp]
        public void RunBeforeAnyTests()
        {
            KsiProvider.SetCryptoProvider(new MonoCryptoProvider());
            //KsiProvider.SetCryptoProvider(new MSCryptoProvider());
        }
    }
}