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
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using NUnit.Framework;

namespace Guardtime.KSI.Trust
{
    [TestFixture]
    public class PkiTrustStoreProviderTests
    {
        [Test]
        public void VerifyTest()
        {
            byte[] data;
            using (FileStream stream = new FileStream("resources/trust/pkitrustprovider/data.bin", FileMode.Open))
            {
                data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);
            }

            byte[] sigBytes;
            using (FileStream stream = new FileStream("resources/trust/pkitrustprovider/sigbytes.bin", FileMode.Open))
            {
                sigBytes = new byte[stream.Length];
                stream.Read(sigBytes, 0, (int)stream.Length);
            }

            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(null,
                new CertificateSubjectRdnSelector("E=publications@guardtime.com"));

            trustStoreProvider.Verify(data, sigBytes);

            Assert.Throws<PkiVerificationErrorException>(delegate
            {
                trustStoreProvider.Verify(null, sigBytes);
            });

            Assert.Throws<PkiVerificationErrorException>(delegate
            {
                trustStoreProvider.Verify(data, null);
            });
        }
    }
}