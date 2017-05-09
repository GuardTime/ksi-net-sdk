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
using System.Reflection;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class CalendarHashChainTests
    {
        [Test]
        public void TestCalendarHashChainOk()
        {
            CalendarHashChain calendarHashChain = GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Ok);
            Assert.AreEqual(26, calendarHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestCalendarHashChainOkMissingOptionals()
        {
            CalendarHashChain calendarHashChain = GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Ok_Missing_Optionals);
            Assert.AreEqual(25, calendarHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestCalendarHashChainInvalidType()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Type);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Invalid tag type! Class: CalendarHashChain; Type: 0x803;"));
        }

        [Test]
        public void TestCalendarHashChainInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag"));
        }

        [Test]
        public void TestCalendarHashChainInvalidMissingInputHash()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in calendar hash chain"));
        }

        [Test]
        public void TestCalendarHashChainInvalidMissingLinks()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Links);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Links are missing in calendar hash chain"));
        }

        [Test]
        public void TestCalendarHashChainInvalidMissingPublicationTime()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Publication_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one publication time must exist in calendar hash chain"));
        }

        [Test]
        public void TestCalendarHashChainInvalidMultipleAggregationTime()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Aggregation_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one aggregation time is allowed in calendar hash chain"));
        }

        [Test]
        public void TestCalendarHashChainInvalidMultipleInputHash()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in calendar hash chain"));
        }

        [Test]
        public void TestCalendarHashChainInvalidMultiplePublicationTime()
        {
            Assert.That(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Publication_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one publication time must exist in calendar hash chain"));
        }

        /// <summary>
        /// Test calendar hash chain with changed hash algorithm
        /// </summary>
        [Test]
        public void TestCalendarHashChainOkChangedAlgorithm()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            using (Stream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.CalendarHashChain_Ok_Changed_Algorithm), FileMode.Open))
            {
                IKsiSignature signature = new KsiSignatureFactory().Create(stream);
                VerificationContext context = new VerificationContext(signature);
                VerificationResult result = rule.Verify(context);

                Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode);
            }
        }

        [Test]
        public void ToStringTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type linkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");

            CalendarHashChain tag = TestUtil.GetCompositeTag<CalendarHashChain>(Constants.CalendarHashChain.TagType,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1),
                    new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 0),
                    new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                    // add links
                    (ITlvTag)Activator.CreateInstance(linkType, new ImprintTag((uint)LinkDirection.Left, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })))
                });

            CalendarHashChain tag2 = new CalendarHashChain(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        private static CalendarHashChain GetCalendarHashChainFromFile(string file)
        {
            using (TlvReader reader = new TlvReader(new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open)))
            {
                CalendarHashChain calendarHashChain = new CalendarHashChain(reader.ReadTag());

                return calendarHashChain;
            }
        }
    }
}