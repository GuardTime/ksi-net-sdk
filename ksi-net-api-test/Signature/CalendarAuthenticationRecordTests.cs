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

using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class CalendarAuthenticationRecordTests
    {
        [Test]
        public void TestCalendarAuthenticationRecordOk()
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Ok);
            Assert.AreEqual(2, calendarAuthenticationRecord.Count, "Invalid amount of child TLV objects");

            PublicationData publicationData = new PublicationData(1398902400,
                new DataHash(Base16.Decode("01C45A4D73815CBECD5493197513A6C2C9058B0B16B99A64805368A7186D528E8B")), false, true);
            Assert.IsTrue(calendarAuthenticationRecord.PublicationData.Equals(publicationData));
            SignatureData signatureData =
                new SignatureData(new RawTag(0xb, false, false,
                    Base16.Decode(
                        "0116312E322E3834302E3131333534392E312E312E3131008002010098D9A4D14722BB2C22425AC9112FBF6A2491B7051AD0CBFD8153E669BFCC6CDF20EEC80F7FCC7236985A4F83871DD6E245470BCA323A3902035B78764DDC4C6EB42416A3A7D7E5CEF6ED6AE8FADA668413758CF7DE1E9565EDF646170286D0F43CA30491DD3407B53DEEDDCBD2620057AB6580E3D3E938AE44EABAF3282357EEBB7B2325616755A1F20B3A78DE2F636DE10F7CCD75B6C5BB80EFEBA216F9BF1A302DCB93B9D3E3E9754620E6D8EC8672C5329CBBB00A9A4617242950D68B8A55CBA77E69DECDD49DD96F69FAA6BFBB0EF48A913F5F26AFA01FB08192D62123FC644BA2978CAF147229BD5702663494983A40ED77AA5016EAABC1FE8456DC17D40304C246B139")));
            Assert.IsTrue(calendarAuthenticationRecord.SignatureData.Equals(signatureData));
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMissingPublicationData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Missing_Publication_Data);
            }, "Only one publication data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMissingSignatureData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Missing_Signature_Data);
            }, "Only one signature data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMultiplePublicationData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Multiple_Publication_Data);
            }, "Only one publication data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMultipleSignatureData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Multiple_Signature_Data);
            }, "Only one signature data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidType()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Type);
            }, "Invalid calendar authentication record type: 2054");
        }

        [Test]
        public void ToStringTest()
        {
            CalendarAuthenticationRecord tag = TestUtil.GetCompositeTag<CalendarAuthenticationRecord>(Constants.CalendarAuthenticationRecord.TagType,
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
                    TestUtil.GetCompositeTag<SignatureData>(Constants.SignatureData.TagType,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.SignatureData.SignatureTypeTagType, false, false, "Test SignatureType"),
                            new RawTag(Constants.SignatureData.SignatureValueTagType, false, false, new byte[] { 0x2 }),
                            new RawTag(Constants.SignatureData.CertificateIdTagType, false, false, new byte[] { 0x3 }),
                            new StringTag(Constants.SignatureData.CertificateRepositoryUriTagType, false, false, "Test CertificateRepositoryUri")
                        })
                });

            CalendarAuthenticationRecord tag2 = new CalendarAuthenticationRecord(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        private static CalendarAuthenticationRecord GetCalendarAuthenticationRecordFromFile(string file)
        {
            using (TlvReader reader = new TlvReader(new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open)))
            {
                CalendarAuthenticationRecord calendarAuthenticationRecord = new CalendarAuthenticationRecord(reader.ReadTag());

                return calendarAuthenticationRecord;
            }
        }
    }
}