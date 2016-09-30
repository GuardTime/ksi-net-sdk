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

using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Publications file tests with static response
    /// </summary>
    [TestFixture]
    public class PublicationsFileStaticTest
    {
        /// <summary>
        /// Test signing and verifying
        /// </summary>
        [Test]
        public void GetPublicationsFileStaticTest()
        {
            Ksi ksi = GetKsi();

            IPublicationsFile pubFile = ksi.GetPublicationsFile();
            Assert.AreEqual(1455494400, pubFile.GetLatestPublication().PublicationData.PublicationTime, "Unexpected last publication time");
        }

        private static Ksi GetKsi()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol();

            return new Ksi(new KsiService(protocol, new ServiceCredentials("test", "test"), protocol, new ServiceCredentials("test", "test"), protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com")))));
        }
    }
}