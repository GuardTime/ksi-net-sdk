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

using Guardtime.KSI.Test.Crypto;
using NUnit.Framework;

namespace Guardtime.KSI.Test
{
    [TestFixture]
    public class CryptoTestFactoryTests
    {
        [Test]
        public void CreateProviderTest()
        {
            string typeName = CryptoTestFactory.CreateProvider().GetType().FullName;

            switch (CryptoTestFactory.ProviderType)
            {
                case CryptoProviderType.Microsoft:
                    Assert.AreEqual("Guardtime.KSI.Crypto.Microsoft.MicrosoftCryptoProvider", typeName, "Invalid crypto provider type name.");
                    break;
                case CryptoProviderType.BouncyCastle:
                    Assert.AreEqual("Guardtime.KSI.Crypto.BouncyCastle.BouncyCastleCryptoProvider", typeName, "Invalid crypto provider type name.");
                    break;
            }
        }

        [Test]
        public void CreateDataHasherTest()
        {
            string typeName = CryptoTestFactory.CreateDataHasher().GetType().FullName;

            switch (CryptoTestFactory.ProviderType)
            {
                case CryptoProviderType.Microsoft:
                    Assert.AreEqual("Guardtime.KSI.Crypto.Microsoft.Hashing.DataHasher", typeName, "Invalid data hasher type name.");
                    break;
                case CryptoProviderType.BouncyCastle:
                    Assert.AreEqual("Guardtime.KSI.Crypto.BouncyCastle.Hashing.DataHasher", typeName, "Invalid data hasher type name.");
                    break;
            }
        }

        [Test]
        public void CreateCertificateSubjectRdnSelectorTest()
        {
            string typeName = CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com").GetType().FullName;

            switch (CryptoTestFactory.ProviderType)
            {
                case CryptoProviderType.Microsoft:
                    Assert.AreEqual("Guardtime.KSI.Crypto.Microsoft.Crypto.CertificateSubjectRdnSelector", typeName, "Invalid CertificateSubjectRdnSelector type name.");
                    break;
                case CryptoProviderType.BouncyCastle:
                    Assert.AreEqual("Guardtime.KSI.Crypto.BouncyCastle.Crypto.CertificateSubjectRdnSelector", typeName, "Invalid CertificateSubjectRdnSelector type name.");
                    break;
            }
        }
    }
}