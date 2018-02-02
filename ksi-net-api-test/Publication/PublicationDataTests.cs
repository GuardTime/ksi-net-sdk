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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Publication
{
    [TestFixture]
    public class PublicationDataTest
    {
        [Test]
        public void PublicationDataContentTest()
        {
            PublicationData publicationData = new PublicationData(1455494400, new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")));
            Assert.AreEqual(new DateTime(2016, 2, 15), publicationData.GetPublicationDate(), "Publication date is invalid.");
            Assert.AreEqual(new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")), publicationData.PublicationHash,
                "Unexpected publication hash.");
        }

        [Test]
        public void PublicationDataFromPublicationStringTest()
        {
            PublicationData pub = new PublicationData("AAAAAA-CVZ2AQ-AANGVK-SV7GJL-36LN65-AVJYZR-6XRZSL-HIMRH3-6GU7WR-YNRY7C-X2XECY-WFQXRB");
            Assert.AreEqual(new DataHash(Base16.Decode("01A6AAA55F992BDF96DF74154E331F5E3992CE8644FBF1A9FB470D8E3E2BEAE416")), pub.PublicationHash, "Unexpected publication hash.");
            Assert.AreEqual(1439596800, pub.PublicationTime, "Unexpected publication time.");
        }

        [Test]
        public void PublicationDataFromPublicationStringNullTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                PublicationData pub = new PublicationData((string)null);
            });

            Assert.AreEqual("publicationString", ex.ParamName, "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PublicationDataFromPublicationStringTooShortTest()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                PublicationData pub = new PublicationData("AAAAAA");
            });

            Assert.That(ex.Message.StartsWith("Publication string base 32 decode failed"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PublicationDataFromPublicationStringInvalidCrc32Test()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                PublicationData pub = new PublicationData("AAAAAA-CVZ2AQ-AANGVK-SV7GJL-36LN65-AVJYZR-6XRZSL-HIMRH3-6GU7WR-YNRY7C-X2XECY-WFQXRA");
            });

            Assert.That(ex.Message.StartsWith("Publication string CRC 32 check failed"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void ToStringTest()
        {
            PublicationData tag =
                TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                        new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                            new DataHash(HashAlgorithm.Sha2256,
                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                    });

            PublicationData tag2 = new PublicationData(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}