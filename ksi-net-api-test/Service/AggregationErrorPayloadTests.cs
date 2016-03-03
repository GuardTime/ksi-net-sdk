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

using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Service
{
    [TestFixture]
    public class AggregationErrorPayloadTests
    {
        [Test]
        public void ToStringTest()
        {
            AggregationErrorPayload tag = TestUtil.GetCompositeTag<AggregationErrorPayload>(Constants.AggregationErrorPayload.TagType, new ITlvTag[]
            {
                new IntegerTag(Constants.KsiPduPayload.StatusTagType, false, false, 1),
                new StringTag(Constants.KsiPduPayload.ErrorMessageTagType, false, false, "Test Error message")
            });

            AggregationErrorPayload tag2 = new AggregationErrorPayload(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}