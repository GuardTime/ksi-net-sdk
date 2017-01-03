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

using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Test.Service
{
    public class StaticServiceTestsBase
    {
        protected static Ksi GetStaticKsi(byte[] requestResult, ulong requestId = 0, IKsiSignatureFactory ksiSignatureFactory = null, PduVersion pduVersion = PduVersion.v2)
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = requestResult
            };

            return
                new Ksi(
                    new TestKsiService(protocol, new ServiceCredentials(Properties.Settings.Default.HttpSigningServiceUser, Properties.Settings.Default.HttpSigningServicePass),
                        protocol, new ServiceCredentials(Properties.Settings.Default.HttpExtendingServiceUser, Properties.Settings.Default.HttpExtendingServicePass), protocol,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), requestId, pduVersion),
                    ksiSignatureFactory);
        }
    }
}