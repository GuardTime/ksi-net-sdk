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
using System.Net;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Service;
using Guardtime.KSI.Service.Tcp;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class TcpKsiServiceProtocolTests : StaticServiceTestsBase
    {
        [Test]
        public void CreateHttpServiceProtocolWithoutIp()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new TcpKsiSigningServiceProtocol(null, 0, 0);
            });

            Assert.AreEqual("ipAddress", ex.ParamName);
        }

        [Test]
        public void CreateHttpServiceProtocolWithInvalidTimeout()
        {
            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                new TcpKsiSigningServiceProtocol(new IPAddress(new byte[] { 127, 0, 0, 1 }), 0, 0, 0);
            });
            Assert.That(ex.Message.StartsWith("Buffer size should be a positive integer"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginSignWithHashNullTest()
        {
            TcpKsiSigningServiceProtocol protocol = new TcpKsiSigningServiceProtocol(new IPAddress(new byte[] { 127, 0, 0, 1 }), 0);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                protocol.BeginSign(null, 1, null, null);
            });
            Assert.AreEqual("data", ex.ParamName);
        }

        [Test]
        public void EndSignInvalidAsyncResultTest()
        {
            TcpKsiSigningServiceProtocol protocol = new TcpKsiSigningServiceProtocol(new IPAddress(new byte[] { 127, 0, 0, 1 }), 0);

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                protocol.EndSign(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid IAsyncResult"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndSignWithAsyncResultDisposedTest()
        {
            TcpKsiSigningServiceProtocol protocol = new TcpKsiSigningServiceProtocol(new IPAddress(new byte[] { 127, 0, 0, 1 }), 0);
            KsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(KsiServiceRequestType.Sign, new byte[] { 1, 2, 3 }, 12345, null, null);
            asyncResult.Dispose();

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                protocol.EndSign(asyncResult);
            });

            Assert.That(ex.Message.StartsWith("Provided async result is already disposed. Possibly using the same async result twice when ending request"),
                "Unexpected exception message: " + ex.Message);
        }
    }
}