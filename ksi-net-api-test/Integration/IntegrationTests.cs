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
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Test.Integration
{
    public class IntegrationTests
    {
        private static readonly HttpKsiServiceProtocol HttpKsiServiceProtocol =
            new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl, Settings.Default.HttpPublicationsFileUrl, 10000);

        private static readonly HttpKsiServiceProtocol HttpKsiServiceProtocolInvalidUrls =
            new HttpKsiServiceProtocol("http://invalid.signing.service.url", "http://invalid.extending.service.url",
                "http://invalid.publications.file.url", 10000);

        private static readonly TcpKsiServiceProtocol TcpKsiServiceProtocol = new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceUrl),
            Settings.Default.TcpSigningServicePort, 10000);

        private static readonly TcpKsiServiceProtocol TcpKsiServiceProtocolInvalidPort = new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceUrl), 2847,
            10000);

        public static KsiService HttpKsiService = GetHttpKsiService();

        public static object[] KsiServiceTestCases =
        {
            new object[]
            {
                HttpKsiService
            }
        };

        public static object[] HttpTestCases =
        {
            new object[]
            {
                new Ksi(HttpKsiService)
            }
        };

        protected static object[] HttpTestCasesInvalidSigningPass =
        {
            new object[]
            {
                new Ksi(
                    GetHttpKsiServiceWithInvalidSigningPass())
            }
        };

        protected static object[] HttpTestCasesInvalidExtendingPass =
        {
            new object[]
            {
                new Ksi(
                    GetHttpKsiServiceWithInvalidExtendingPass())
            }
        };

        protected static object[] HttpTestCasesInvalidSigningUrl =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        HttpKsiServiceProtocolInvalidUrls,
                        new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                            GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                        HttpKsiServiceProtocol,
                        new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                            GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                        HttpKsiServiceProtocol,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        TestSetup.PduVersion))
            }
        };

        protected static object[] HttpTestCasesInvalidExtendingUrl =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        HttpKsiServiceProtocol,
                        new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                            GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                        HttpKsiServiceProtocolInvalidUrls,
                        new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                            GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                        HttpKsiServiceProtocol,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        TestSetup.PduVersion))
            }
        };

        protected static object[] HttpTestCasesInvalidPublicationsFileUrl =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        HttpKsiServiceProtocol,
                        new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                            GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                        HttpKsiServiceProtocol,
                        new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                            GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                        HttpKsiServiceProtocolInvalidUrls,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        TestSetup.PduVersion))
            }
        };

        protected static object[] TcpTestCases =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        TcpKsiServiceProtocol,
                        new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                            GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                        null,
                        null,
                        HttpKsiServiceProtocol,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        TestSetup.PduVersion))
            }
        };

        protected static object[] TcpTestCasesInvalidPass =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        TcpKsiServiceProtocol,
                        new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass + "x",
                            GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                        null,
                        null,
                        null,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        TestSetup.PduVersion))
            }
        };

        protected static object[] TcpTestCasesInvalidPort =
        {
            new object[]
            {
                new Ksi(
                    new KsiService(
                        TcpKsiServiceProtocolInvalidPort,
                        new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                            GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                        null,
                        null,
                        null,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                        TestSetup.PduVersion))
            }
        };

        protected static KsiService GetHttpKsiService(PduVersion? pduVersion = null)
        {
            return new KsiService(
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), pduVersion ?? TestSetup.PduVersion);
        }

        protected static KsiService GetTcpKsiService(PduVersion? pduVersion = null)
        {
            return new KsiService(
                TcpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass,
                    GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                null,
                null,
                null,
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), pduVersion ?? TestSetup.PduVersion);
        }

        protected static KsiService GetHttpKsiServiceWithInvalidSigningPass()
        {
            return new KsiService(
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass + "x",
                    GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        protected static KsiService GetHttpKsiServiceWithInvalidExtendingPass()
        {
            return new KsiService(
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass + "x",
                    GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        protected static KsiService GetHttpKsiServiceWithDefaultPduVersion()
        {
            return new KsiService(
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                HttpKsiServiceProtocol,
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))));
        }

        protected static KsiService GetService(PduVersion version, HashAlgorithm aggregatorHmacAlgo, HashAlgorithm extenderHmacAlgo)
        {
            return new KsiService(
                    new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl, Settings.Default.HttpPublicationsFileUrl, 10000),
                        new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass, aggregatorHmacAlgo),
                    new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl, Settings.Default.HttpPublicationsFileUrl, 10000),
                        new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass, extenderHmacAlgo),
                    new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl, Settings.Default.HttpPublicationsFileUrl, 10000),
                        new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), version);
        }

        protected class TestAsyncResult : IAsyncResult
        {
            public object AsyncState => null;

            public WaitHandle AsyncWaitHandle => new ManualResetEvent(false);

            public bool CompletedSynchronously => false;

            public bool IsCompleted => false;
        }

        protected static HashAlgorithm GetHashAlgorithm(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return HashAlgorithm.Default;
            }

            HashAlgorithm algorithm = HashAlgorithm.GetByName(name);

            if (algorithm == null)
            {
                throw new Exception("Invalid hmac algorithm name value in config. Name: " + name);
            }

            return algorithm;
        }
    }
}