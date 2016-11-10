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
using System.Reflection;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class ExtendResponsePayloadTests
    {
        [Test]
        public void ToStringTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type linkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");

            ExtendResponsePayload tag = TestUtil.GetCompositeTag<ExtendResponsePayload>(Constants.ExtendResponsePayload.TagType, new ITlvTag[]
            {
                new IntegerTag(Constants.KsiPduPayload.RequestIdTagType, false, false, 2),
                new IntegerTag(Constants.KsiPduPayload.StatusTagType, false, false, 0),
                new StringTag(Constants.KsiPduPayload.ErrorMessageTagType, false, false, "Test error message."),
                new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 1),
                TestUtil.GetCompositeTag<CalendarHashChain>(Constants.CalendarHashChain.TagType,
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
                    })
            });

            ExtendResponsePayload tag2 = new ExtendResponsePayload(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}