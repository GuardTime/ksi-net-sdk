using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Utils
{
    [TestClass]
    public class UtilTests
    {
        [TestMethod]
        public void CloneTest()
        {
            byte[] value = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
            byte[] clone = Util.Clone(value);
            Assert.AreNotEqual(value, clone, "Value and clone should not be the same objects.");
            Assert.IsTrue(Util.IsArrayEqual(value, clone), "Value and clone should have same content.");

            clone[0] = 0;
            Assert.IsFalse(Util.IsArrayEqual(value, clone), "Value and modified clone should have different content.");
        }

        [TestMethod]
        public void CloneTest1()
        {
            byte[] value = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
            byte[] test = new byte[] {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30};
            byte[] clone = Util.Clone(value, 2, 28);
            Assert.AreNotEqual(value, clone, "Value and clone should not be the same objects.");
            Assert.IsTrue(Util.IsArrayEqual(clone, test), "Test and clone should have same content.");

            clone[1] = 0;
            Assert.IsFalse(Util.IsArrayEqual(value, clone), "Test and modified clone should have different content.");
        }

        [TestMethod]
        public void IsOneValueEqualToTest()
        {
            Assert.IsTrue(Util.IsOneValueEqualTo(1, 0, 1, 2, 3), "Only one value should be equal.");
            Assert.IsTrue(Util.IsOneValueEqualTo(1, 1, 0, 2, 3), "Only one value should be equal.");
            Assert.IsTrue(Util.IsOneValueEqualTo(1, 0, 0, 2, 1), "Only one value should be equal.");
            Assert.IsFalse(Util.IsOneValueEqualTo(1, 0, 1, 2, 1), "More than one value should be equal.");
            Assert.IsFalse(Util.IsOneValueEqualTo(1, 1, 1, 0, 3), "More than one value should be equal.");
            Assert.IsFalse(Util.IsOneValueEqualTo(1, 3, 2, 0, 3), "No values should be equal.");
        }
    }
}