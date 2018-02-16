/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Utils
{
    [TestFixture]
    public class UtilTests
    {
        [Test]
        public void CloneTest()
        {
            byte[] value = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
            byte[] clone = Util.Clone(value);
            Assert.IsTrue(Util.IsArrayEqual(value, clone), "Value and clone should have same content.");

            clone[0] = 0;
            Assert.IsFalse(Util.IsArrayEqual(value, clone), "Value and modified clone should have different content.");
        }

        [Test]
        public void CloneTest1()
        {
            byte[] value = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
            byte[] test = new byte[] { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30 };
            byte[] clone = Util.Clone(value, 2, 28);
            Assert.AreNotEqual(value, clone, "Value and clone should not be the same objects.");
            Assert.IsTrue(Util.IsArrayEqual(clone, test), "Test and clone should have same content.");

            clone[1] = 0;
            Assert.IsFalse(Util.IsArrayEqual(value, clone), "Test and modified clone should have different content.");
        }

        [Test]
        public void IsOneValueEqualToTest()
        {
            Assert.IsTrue(Util.IsOneValueEqualTo(1, 0, 1, 2, 3), "Only one value should be equal.");
            Assert.IsTrue(Util.IsOneValueEqualTo(1, 1, 0, 2, 3), "Only one value should be equal.");
            Assert.IsTrue(Util.IsOneValueEqualTo(1, 0, 0, 2, 1), "Only one value should be equal.");
            Assert.IsFalse(Util.IsOneValueEqualTo(1, 0, 1, 2, 1), "More than one value should be equal.");
            Assert.IsFalse(Util.IsOneValueEqualTo(1, 1, 1, 0, 3), "More than one value should be equal.");
            Assert.IsFalse(Util.IsOneValueEqualTo(1, 3, 2, 0, 3), "No values should be equal.");
        }

        [Test]
        public void IsArrayPartEqualTest()
        {
            byte[] value = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
            byte[] test = new byte[] { 0, 0, 3, 4, 5, 6, 7, 8, 9, 0, 0 };

            Assert.IsTrue(Util.IsArrayEqual(value, test, 2, 7), "Array parts should be equal. Index: 2; Count: 7");
            Assert.IsFalse(Util.IsArrayEqual(value, test, 2, 8), "Array parts should not be equal. Index: 2; Count: 8");
            Assert.IsFalse(Util.IsArrayEqual(value, test, 1, 7), "Array parts should be equal. Index: 1; Count: 7");
        }

        [Test]
        public void IsArrayEqualTest()
        {
            Assert.IsTrue(Util.IsArrayEqual<byte[]>(null, null));
            Assert.IsFalse(Util.IsArrayEqual(new byte[] { 1 }, null));
            Assert.IsFalse(Util.IsArrayEqual(null, new byte[] { 1 }));
            Assert.IsTrue(Util.IsArrayEqual(new byte[] { 1 }, new byte[] { 1 }));
            Assert.IsFalse(Util.IsArrayEqual(new byte[] { 1 }, new byte[] { 2 }));
        }
    }
}