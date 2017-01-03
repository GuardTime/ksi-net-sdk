/*
 * Copyright 2013-2016 Guardtime, Inc.
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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Publication
{
    [TestFixture]
    public class PublicationDataTest
    {
        [Test]
        public void PublicationDataContentTest()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_Extended), FileMode.Open))
            {
                IKsiSignature signature = new KsiSignatureFactory().Create(stream);
                PublicationRecordInSignature publicationRecord = signature.PublicationRecord;

                string code = publicationRecord.PublicationData.GetPublicationString();
                DateTime date = publicationRecord.PublicationData.GetPublicationDate();

                Assert.AreEqual("AAAAAA-CWYEKQ-AAIYPA-UJ4GRT-HXMFBE-OTB4AB-XH3PT3-KNIKGV-PYCJXU-HL2TN4-RG6SCC-3ZGSBM", code, "Publication string is invalid.");
                Assert.AreEqual(new DateTime(2016, 2, 15), date, "Publication date is invalid.");
                Assert.AreEqual(3, publicationRecord.PublicationReferences.Count, "Invalid publication reference count.");
                Assert.AreEqual("Financial Times, ISSN: 0307-1766, 2016-02-17", publicationRecord.PublicationReferences[0], "Invalid first publication reference.");
                Assert.AreEqual("Äripäev, ISSN: 1406-2585, 17.02.2016", publicationRecord.PublicationReferences[1], "Invalid second publication reference.");
                Assert.AreEqual("https://twitter.com/Guardtime/status/699919571084558336", publicationRecord.PublicationReferences[2], "Invalid third publication reference.");
            }
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