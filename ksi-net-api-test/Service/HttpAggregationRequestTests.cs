using Microsoft.VisualStudio.TestTools.UnitTesting;
using Guardtime.KSI.Service;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Guardtime.KSI.Service
{
    [TestClass]
    public class HttpAggregationRequestTests
    {
        [TestMethod]
        public void TestHttpAggregationRequest()
        {
            var request = new HttpAggregationRequest();
        }
    }
}