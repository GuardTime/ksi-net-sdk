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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Test.Service
{
    public class StaticServiceTestsBase
    {
        protected static Ksi GetStaticKsi(string requestResultFile, ulong requestId = 0, IKsiSignatureFactory ksiSignatureFactory = null, PduVersion pduVersion = PduVersion.v2,
                                          HashAlgorithm signingMacAlgorithm = null, HashAlgorithm extendingMacAlgorithm = null)
        {
            return GetStaticKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, requestResultFile)), requestId, ksiSignatureFactory, pduVersion, signingMacAlgorithm,
                extendingMacAlgorithm);
        }

        protected static Ksi GetStaticKsi(byte[] requestResult, ulong requestId = 0, IKsiSignatureFactory ksiSignatureFactory = null, PduVersion pduVersion = PduVersion.v2,
                                          HashAlgorithm signingMacAlgorithm = null, HashAlgorithm extendingMacAlgorithm = null)
        {
            return new Ksi(GetStaticKsiService(requestResult, requestId, pduVersion, signingMacAlgorithm, extendingMacAlgorithm), ksiSignatureFactory);
        }

        protected static IKsiService GetStaticKsiService(byte[] requestResult, ulong requestId = 0,
                                                         PduVersion pduVersion = PduVersion.v2,
                                                         HashAlgorithm signingMacAlgorithm = null, HashAlgorithm extendingMacAlgorithm = null)
        {
            return GetStaticKsiService(new TestKsiServiceProtocol
                {
                    RequestResult = requestResult,
                },
                requestId, pduVersion, signingMacAlgorithm, extendingMacAlgorithm);
        }

        protected static IKsiService GetStaticKsiService(TestKsiServiceProtocol protocol, ulong requestId = 0,
                                                         PduVersion pduVersion = PduVersion.v2,
                                                         HashAlgorithm signingMacAlgorithm = null, HashAlgorithm extendingMacAlgorithm = null)
        {
            return
                new TestKsiService(
                    protocol,
                    new ServiceCredentials(TestConstants.ServiceUser, TestConstants.ServicePass, signingMacAlgorithm),
                    protocol,
                    new ServiceCredentials(TestConstants.ServiceUser, TestConstants.ServicePass, extendingMacAlgorithm),
                    protocol,
                    new PublicationsFileFactory(
                        new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                            CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), requestId, pduVersion);
        }

        protected class TestAsyncResult : IAsyncResult
        {
            public object AsyncState => null;

            public WaitHandle AsyncWaitHandle => new ManualResetEvent(false);

            public bool CompletedSynchronously => false;

            public bool IsCompleted => false;
        }
    }
}