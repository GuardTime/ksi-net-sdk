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

using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Service;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class HttpKsiServiceProtocolTests : StaticServiceTestsBase
    {
        [Test]
        public void BeginSignWithHashNullTest()
        {
            HttpKsiServiceProtocol protocol = new HttpKsiServiceProtocol("service-url", null, null);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                protocol.BeginSign(null, 1, null, null);
            });
            Assert.AreEqual("data", ex.ParamName);
        }

        [Test]
        public void EndSignInvalidAsyncResultTest()
        {
            HttpKsiServiceProtocol protocol = new HttpKsiServiceProtocol(null, null, null);

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                protocol.EndSign(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid IAsyncResult"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void CreateHttpServiceProtocolWithInvalidTimeout()
        {
            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                new HttpKsiServiceProtocol(null, null, null, -1);
            });

            Assert.That(ex.Message.StartsWith("Request timeout should be in milliseconds"), "Unexpected exception message: " + ex.Message);
        }
    }
}