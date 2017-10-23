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

using System.Net;
using System.Security.Cryptography.X509Certificates;
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
        public static KsiService[] HttpKsiService = new KsiService[]
        {
            GetHttpKsiService()
        };

        public static KsiService[] KsiServices = GetKsiServices();

        public static KsiService[] GetKsiServices()
        {
            return new KsiService[]
            {
                GetHttpKsiService(),
                GetTcpKsiService()
            };
        }

        protected static object[] KsiServicesWithInvalidExtendingPass = new object[]
        {
            GetHttpKsiServiceWithInvalidExtendingPass(),
            GetTcpKsiServiceWithInvalidExtendingPass()
        };

        protected static object[] KsiServicesWithInvalidSigningPass = new object[]
        {
            GetHttpKsiServiceWithInvalidSigningPass(),
            GetTcpKsiServiceWithInvalidSigningPass()
        };

        public static Ksi[] KsiList = new Ksi[]
        {
            new Ksi(GetHttpKsiService()),
            new Ksi(GetTcpKsiService())
        };

        public static Ksi[] HttpKsi = new Ksi[]
        {
            new Ksi(GetHttpKsiService())
        };

        protected static object[] KsiListWithInvalidSigningPass =
            new object[]
            {
                new Ksi(GetHttpKsiServiceWithInvalidSigningPass()),
                new Ksi(GetTcpKsiServiceWithInvalidSigningPass()),
            };

        protected static object[] KsiListWithInvalidExtendingPass =
            new object[]
            {
                new Ksi(GetHttpKsiServiceWithInvalidExtendingPass()),
                new Ksi(GetTcpKsiServiceWithInvalidExtendingPass())
            };

        protected static Ksi[] HttpKsiWithInvalidSigningUrl = new Ksi[]
        {
            new Ksi(new KsiService(
                GetHttpKsiServiceProtocolInvalidUrls(),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                TestSetup.PduVersion))
        };

        protected static Ksi[] HttpKsiWithInvalidExtendingUrl = new Ksi[]
        {
            new Ksi(new KsiService(
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocolInvalidUrls(),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                TestSetup.PduVersion))
        };

        protected static Ksi[] HttpKsiWithInvalidPublicationsFileUrl = new Ksi[]
        {
            new Ksi(
                new KsiService(
                    GetHttpKsiServiceProtocol(),
                    new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                        TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                    GetHttpKsiServiceProtocol(),
                    new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                        TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                    GetHttpKsiServiceProtocolInvalidUrls(),
                    new PublicationsFileFactory(
                        new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                    TestSetup.PduVersion))
        };

        protected static Ksi[] TcpKsiWithInvalidSigningPort = new Ksi[]
        {
            new Ksi(new KsiService(
                GetTcpKsiServiceProtocolInvalidSigningPort(),
                new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                GetTcpKsiServiceProtocolInvalidSigningPort(),
                new ServiceCredentials(Settings.Default.TcpExtendingServiceUser, Settings.Default.TcpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                TestSetup.PduVersion))
        };

        protected static Ksi[] TcpKsiWithInvalidExtendingPort = new Ksi[]
        {
            new Ksi(new KsiService(
                GetTcpKsiServiceProtocolInvalidExtendingPort(),
                new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                GetTcpKsiServiceProtocolInvalidExtendingPort(),
                new ServiceCredentials(Settings.Default.TcpExtendingServiceUser, Settings.Default.TcpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                TestSetup.PduVersion))
        };

        public static KsiService GetHttpKsiService(PduVersion? pduVersion = null)
        {
            return new KsiService(
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), pduVersion ?? TestSetup.PduVersion);
        }

        protected static KsiService GetTcpKsiService(PduVersion? pduVersion = null)
        {
            TcpKsiServiceProtocol tcpKsiServiceProtocol = GetTcpKsiServiceProtocol();

            return new KsiService(
                tcpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                tcpKsiServiceProtocol,
                new ServiceCredentials(Settings.Default.TcpExtendingServiceUser, Settings.Default.TcpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), pduVersion ?? TestSetup.PduVersion);
        }

        private static KsiService GetHttpKsiServiceWithInvalidSigningPass()
        {
            return new KsiService(
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass + "x",
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        private static KsiService GetTcpKsiServiceWithInvalidSigningPass()
        {
            return new KsiService(
                GetTcpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass + "x",
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                GetTcpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.TcpExtendingServiceUser, Settings.Default.TcpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        private static KsiService GetHttpKsiServiceWithInvalidExtendingPass()
        {
            return new KsiService(
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass + "x",
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        private static KsiService GetTcpKsiServiceWithInvalidExtendingPass()
        {
            return new KsiService(
                GetTcpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                GetTcpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.TcpExtendingServiceUser, Settings.Default.TcpExtendingServicePass + "x",
                    TestUtil.GetHashAlgorithm(Settings.Default.TcpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        protected static KsiService GetHttpKsiServiceWithoutSigningUrl()
        {
            return new KsiService(
                new HttpKsiServiceProtocol(null, Settings.Default.HttpExtendingServiceUrl, Settings.Default.HttpPublicationsFileUrl, 10000),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        protected static KsiService GetHttpKsiServiceWithoutExtendingUrl()
        {
            return new KsiService(
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, null, Settings.Default.HttpPublicationsFileUrl, 10000),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(),
                TestSetup.PduVersion);
        }

        protected static KsiService GetHttpKsiServiceWithDefaultPduVersion()
        {
            return new KsiService(
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpSigningServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass,
                    TestUtil.GetHashAlgorithm(Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                GetHttpKsiServiceProtocol(),
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))));
        }

        private static HttpKsiServiceProtocol GetHttpKsiServiceProtocol()
        {
            return new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl, Settings.Default.HttpPublicationsFileUrl, 10000);
        }

        private static HttpKsiServiceProtocol GetHttpKsiServiceProtocolInvalidUrls()
        {
            return
                new HttpKsiServiceProtocol("http://invalid.signing.service.url", "http://invalid.extending.service.url",
                    "http://invalid.publications.file.url", 10000);
        }

        private static TcpKsiServiceProtocol GetTcpKsiServiceProtocol()
        {
            return new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceIp),
                Settings.Default.TcpSigningServicePort, IPAddress.Parse(Settings.Default.TcpExtendingServiceIp), Settings.Default.TcpExtendingServicePort, 10000);
        }

        private static TcpKsiServiceProtocol GetTcpKsiServiceProtocolInvalidSigningPort()
        {
            return new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceIp), 2847,
                IPAddress.Parse(Settings.Default.TcpExtendingServiceIp), Settings.Default.TcpExtendingServicePort, 10000);
        }

        private static TcpKsiServiceProtocol GetTcpKsiServiceProtocolInvalidExtendingPort()
        {
            return new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceIp), Settings.Default.TcpSigningServicePort,
                IPAddress.Parse(Settings.Default.TcpExtendingServiceIp), 2847, 10000);
        }
    }
}