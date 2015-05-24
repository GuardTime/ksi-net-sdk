using System;
using System.Collections;
using NUnit.Framework;

namespace Guardtime.KSI.Util
{
    [TestFixture]
    public class EmptyEnumeratorTests
    {
        [Test]
        public void TestMoveNext()
        {
            IEnumerator enumerator = new EmptyEnumerator<int>();
            Assert.IsFalse(enumerator.MoveNext());
        }

        [Test, ExpectedException(typeof(InvalidOperationException))]
        public void TestCurrentPropertyException()
        {
            IEnumerator enumerator = new EmptyEnumerator<int>();
            var value = enumerator.Current;
        }
    }
}