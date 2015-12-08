using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ksi_net_api_mono;
using NUnit.Framework;

namespace Guardtime.KSI
{
    [SetUpFixture]
    public class TestSetup
    {
        [SetUp]
        public void RunBeforeAnyTests()
        {
            KsiProvider.Build();
        }
    }
}