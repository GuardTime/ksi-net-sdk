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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Publication
{
    [TestFixture]
    public class PublicationRecordTests
    {
        [Test]
        public void ToStringInPublicationFileTest()
        {
            PublicationRecord tag =
                TestUtil.GetCompositeTag<PublicationRecordInPublicationFile>(Constants.PublicationRecord.TagTypeInPublicationsFile,
                    new ITlvTag[]
                    {
                        TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                            }),
                        new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 1"),
                        new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 2"),
                        new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 1"),
                        new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 2"),
                    });

            PublicationRecord tag2 = new PublicationRecordInPublicationFile(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void ToStringInSignatureTest()
        {
            PublicationRecord tag =
                TestUtil.GetCompositeTag<PublicationRecordInSignature>(Constants.PublicationRecord.TagTypeInSignature,
                    new ITlvTag[]
                    {
                        TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                            }),
                        new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 1"),
                        new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 2"),
                        new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 1"),
                        new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 2"),
                    });

            PublicationRecord tag2 = new PublicationRecordInSignature(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}