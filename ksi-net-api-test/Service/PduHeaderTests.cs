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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class PduHeaderTests
    {
        [Test]
        public void PduHeaderTest()
        {
            PduHeader tag = new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false, new ITlvTag[]
            {
                new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "TestLoginId"),
                new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
            }).BuildTag());

            Assert.AreEqual("TestLoginId", tag.LoginId, "Unexpected login id");
            Assert.AreEqual(1, tag.InstanceId, "Unexpected instance id");
            Assert.AreEqual(2, tag.MessageId, "Unexpected publication time");
        }

        [Test]
        public void PduHeaderWithoutRequestId()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false, new ITlvTag[]
                {
                    new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 2),
                }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one login id must exist in PDU header"));
        }

        [Test]
        public void PduHeaderWithMultipleInstanceIds()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false, new ITlvTag[]
                {
                    new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "TestLoginId"),
                    new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 2),
                    new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 2),
                }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one instance id is allowed in PDU header"));
        }

        [Test]
        public void PduHeaderWithoutMultipleMessageIds()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false, new ITlvTag[]
                {
                    new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "TestLoginId"),
                    new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2),
                    new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one message id is allowed in PDU header"));
        }

        [Test]
        public void ToStringTest()
        {
            PduHeader tag = new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                new ITlvTag[]
                {
                    new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "TestLoginId"),
                    new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                    new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                }).BuildTag());

            PduHeader tag2 = new PduHeader(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());

            tag = new PduHeader("TestLoginId", 1, 2);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}