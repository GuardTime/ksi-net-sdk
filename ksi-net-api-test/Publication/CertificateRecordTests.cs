/*
 * Copyright 2013-2018 Guardtime, Inc.
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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Publication
{
    [TestFixture]
    public class CertificateRecordTests
    {
        [Test]
        public void CertificationRecordOkTest()
        {
            TlvTagBuilder builder = new TlvTagBuilder(Constants.CertificateRecord.TagType, false, false,
                new ITlvTag[]
                {
                    new RawTag(Constants.CertificateRecord.CertificateIdTagType, false, false, new byte[] { 0x2 }),
                    new RawTag(Constants.CertificateRecord.X509CertificateTagType, false, false, new byte[] { 0x3 }),
                });

            CertificateRecord tag = new CertificateRecord(builder.BuildTag());

            Assert.That(Util.IsArrayEqual(new byte[] { 0x2 }, tag.CertificateId.Value), "Unexpected certificate id");
            Assert.That(Util.IsArrayEqual(new byte[] { 0x3 }, tag.X509Certificate.Value), "Unexpected X509 certificate.");
        }

        [Test]
        public void CertificationRecordWithoutCertIdTest()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                TlvTagBuilder builder = new TlvTagBuilder(Constants.CertificateRecord.TagType, false, false,
                    new ITlvTag[]
                    {
                        new RawTag(Constants.CertificateRecord.X509CertificateTagType, false, false, new byte[] { 0x3 }),
                    });

                CertificateRecord tag = new CertificateRecord(builder.BuildTag());
            });

            Assert.That(ex.Message.StartsWith("Exactly one certificate id must exist in certificate record"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void CertificationRecordWithoutCertTest()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                TlvTagBuilder builder = new TlvTagBuilder(Constants.CertificateRecord.TagType, false, false,
                    new ITlvTag[]
                    {
                        new RawTag(Constants.CertificateRecord.CertificateIdTagType, false, false, new byte[] { 0x2 }),
                    });

                CertificateRecord tag = new CertificateRecord(builder.BuildTag());
            });

            Assert.That(ex.Message.StartsWith("Exactly one certificate must exist in certificate record"), "Unexpected exception message: " + ex.Message);
        }

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