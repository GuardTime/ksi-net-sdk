using Microsoft.VisualStudio.TestTools.UnitTesting;
using Guardtime.KSI.Util;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Guardtime.KSI.Util
{
    [TestClass]
    public class EmptyEnumeratorTests
    {
        [TestMethod]
        public void TestMoveNext()
        {
            IEnumerator enumerator = new EmptyEnumerator();
            Assert.IsFalse(enumerator.MoveNext());
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void TestCurrentPropertyException()
        {
            IEnumerator enumerator = new EmptyEnumerator();
            var value = enumerator.Current;
        }
    }
}