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
using Guardtime.KSI.Service;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class KsiPduHeaderTests
    {
        [Test]
        public void ToStringTest()
        {
            KsiPduHeader tag = TestUtil.GetCompositeTag<KsiPduHeader>(Constants.KsiPduHeader.TagType,
                new ITlvTag[]
                {
                    new StringTag(Constants.KsiPduHeader.LoginIdTagType, false, false, "Test Login Id"),
                    new IntegerTag(Constants.KsiPduHeader.InstanceIdTagType, false, false, 1),
                    new IntegerTag(Constants.KsiPduHeader.MessageIdTagType, false, false, 2)
                });

            KsiPduHeader tag2 = new KsiPduHeader(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());

            tag = new KsiPduHeader("Test Login Id", 1, 2);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}