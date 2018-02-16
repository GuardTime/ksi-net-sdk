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
using Guardtime.KSI.Service;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class ExtenderConfigResponsePayloadTests
    {
        [Test]
        public void ExtenderConfigResponsePayloadOk()
        {
            ExtenderConfigResponsePayload conf = new ExtenderConfigResponsePayload(new TlvTagBuilder(Constants.ExtenderConfigResponsePayload.TagType, false, false,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.ExtenderConfigResponsePayload.MaxRequestsTagType, false, false, 1),
                    new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarFirstTimeTagType, false, false, 2),
                    new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarLastTimeTagType, false, false, 3),
                }).BuildTag());

            Assert.AreEqual(1, conf.MaxRequests, "Unexpected max requests");
            Assert.AreEqual(2, conf.CalendarFirstTime, "Unexpected calendar first time");
            Assert.AreEqual(3, conf.CalendarLastTime, "Unexpected calendar last time");
        }

        [Test]
        public void ExtenderConfigResponsePayloadWithMultipleMaxRequests()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtenderConfigResponsePayload(new TlvTagBuilder(Constants.ExtenderConfigResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.ExtenderConfigResponsePayload.MaxRequestsTagType, false, false, 1),
                        new IntegerTag(Constants.ExtenderConfigResponsePayload.MaxRequestsTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one max requests tag is allowed in extender config response payload."));
        }

        [Test]
        public void ExtenderConfigResponsePayloadWithMultipleCalendarFirstTimes()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtenderConfigResponsePayload(new TlvTagBuilder(Constants.ExtenderConfigResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarFirstTimeTagType, false, false, 1),
                        new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarFirstTimeTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one calendar first time tag is allowed in extender config response payload"));
        }

        [Test]
        public void ExtenderConfigResponsePayloadWithMultipleCalendarLastTimes()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtenderConfigResponsePayload(new TlvTagBuilder(Constants.ExtenderConfigResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarLastTimeTagType, false, false, 1),
                        new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarLastTimeTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one calendar last time tag is allowed in extender config response payload"));
        }
    }
}