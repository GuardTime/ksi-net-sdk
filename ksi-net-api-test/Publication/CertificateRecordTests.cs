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
using Guardtime.KSI.Publication;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Publication
{
    [TestFixture]
    public class CertificateRecordTests
    {
        [Test]
        public void ToStringTest()
        {
            CertificateRecord tag =
                TestUtil.GetCompositeTag<CertificateRecord>(Constants.CertificateRecord.TagType,
                    new ITlvTag[]
                    {
                        new RawTag(Constants.CertificateRecord.CertificateIdTagType, false, false, new byte[] { 0x2 }),
                        new RawTag(Constants.CertificateRecord.X509CertificateTagType, false, false, new byte[] { 0x3 }),
                    });

            CertificateRecord tag2 = new CertificateRecord(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}