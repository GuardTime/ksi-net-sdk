/*
 * Copyright 2013-2017 Guardtime, Inc.
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

using System;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Parser
{
    [TestFixture]
    public class TlvReaderTests
    {
        [Test]
        public void TestConstructorWithEncoding()
        {
            using (TlvReader reader = new TlvReader(new MemoryStream(new byte[] { 0x21, 0x4, 0x0, 0x1, 0x2, 0x3 })))
            {
                TlvTag tag = reader.ReadTag();
                Assert.AreEqual(new RawTag(0x1, false, true, new byte[] { 0x0, 0x1, 0x2, 0x3 }), tag, "Reader should output correct tag");
            }
        }

        [Test]
        public void TestReadTagShort()
        {
            using (TlvReader reader = new TlvReader(new MemoryStream(new byte[] { 0x21, 0x4, 0x0, 0x1, 0x2, 0x3 })))
            {
                TlvTag tag = reader.ReadTag();
                Assert.AreEqual(new RawTag(0x1, false, true, new byte[] { 0x0, 0x1, 0x2, 0x3 }), tag, "Reader should output correct tag");
            }
        }

        [Test]
        public void TestReadTagShortWithLongType()
        {
            using (TlvReader reader = new TlvReader(new MemoryStream(new byte[] { 0xa0, 0x33, 0x0, 0x4, 0x0, 0x1, 0x2, 0x3 })))
            {
                Assert.AreEqual(new RawTag(0x33, false, true, new byte[] { 0x0, 0x1, 0x2, 0x3 }), reader.ReadTag(), "Reader should output correct byte array");
            }
        }

        [Test]
        public void TestReadTagLongWithShortType()
        {
            byte[] data = new byte[260];
            data[0] = 0xe0;
            data[1] = 0x1;
            data[2] = 0x1;
            data[3] = 0x0;
            Array.Copy(new byte[256], 0, data, 4, 256);
            using (TlvReader reader = new TlvReader(new MemoryStream(data)))
            {
                Assert.AreEqual(new RawTag(0x1, true, true, new byte[256]), reader.ReadTag(), "Reader should output correct byte array");
            }
        }

        [Test]
        public void TestReadTagLongWithLongType()
        {
            byte[] data = new byte[260];
            data[0] = 0xe2;
            data[1] = 0x57;
            data[2] = 0x1;
            data[3] = 0x0;
            Array.Copy(new byte[256], 0, data, 4, 256);

            using (TlvReader reader = new TlvReader(new MemoryStream(data)))
            {
                Assert.AreEqual(new RawTag(0x257, true, true, new byte[256]), reader.ReadTag(), "Reader should output correct byte array");
            }
        }

        [Test]
        public void TestReadTooShortTag()
        {
            using (TlvReader reader = new TlvReader(new MemoryStream(new byte[] { 0x21 })))
            {
                Assert.Throws<TlvException>(delegate
                {
                    reader.ReadTag();
                }, "Premature end of data");
            }
        }

        [Test]
        public void TestReadDataWithInvalidLength()
        {
            using (TlvReader reader = new TlvReader(new MemoryStream(new byte[] { 0x21, 0x2 })))
            {
                Assert.Throws<TlvException>(delegate
                {
                    reader.ReadTag();
                }, "Premature end of data");
            }
        }
    }
}