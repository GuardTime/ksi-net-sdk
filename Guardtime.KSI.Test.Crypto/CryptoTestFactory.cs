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

using System;
using System.Collections.Generic;
using System.Configuration;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Crypto.BouncyCastle;
using Guardtime.KSI.Crypto.Microsoft;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Test.Crypto
{
    public class CryptoTestFactory
    {
        private static CryptoProviderType _providerType;
        private static bool _isProviderTypeSet;

        public static CryptoProviderType ProviderType
        {
            get
            {
                if (_isProviderTypeSet)
                {
                    return _providerType;
                }

                string providerTypeString = ConfigurationManager.AppSettings["CryptoProviderType"];

                if (string.IsNullOrEmpty(providerTypeString))
                {
                    throw new Exception("Missing crypto provider type.");
                }

                if (!Enum.TryParse(providerTypeString, out _providerType))
                {
                    throw new Exception("Invalid crypto provider type: " + providerTypeString);
                }

                if (_providerType == CryptoProviderType.None)
                {
                    throw new Exception("Crypto provider type not allowed: " + _providerType);
                }

                _isProviderTypeSet = true;

                return _providerType;
            }
        }

        public static ICryptoProvider CreateProvider()
        {
            switch (ProviderType)
            {
                case CryptoProviderType.BouncyCastle:
                    return new BouncyCastleCryptoProvider();
                case CryptoProviderType.Microsoft:
                    return new MicrosoftCryptoProvider();
                default:
                    return null;
            }
        }

        public static IDataHasher CreateDataHasher()
        {
            switch (ProviderType)
            {
                case CryptoProviderType.BouncyCastle:
                    return new KSI.Crypto.BouncyCastle.Hashing.DataHasher(HashAlgorithm.Default);
                case CryptoProviderType.Microsoft:
                    return new KSI.Crypto.Microsoft.Hashing.DataHasher(HashAlgorithm.Default);
                default:
                    return null;
            }
        }

        public static IDataHasher CreateDataHasher(HashAlgorithm algorithm)
        {
            switch (ProviderType)
            {
                case CryptoProviderType.BouncyCastle:
                    return new KSI.Crypto.BouncyCastle.Hashing.DataHasher(algorithm);
                case CryptoProviderType.Microsoft:
                    return new KSI.Crypto.Microsoft.Hashing.DataHasher(algorithm);
                default:
                    return null;
            }
        }

        public static ICertificateSubjectRdnSelector CreateCertificateSubjectRdnSelector(IList<CertificateSubjectRdn> rdnList)
        {
            switch (ProviderType)
            {
                case CryptoProviderType.BouncyCastle:
                    return new KSI.Crypto.BouncyCastle.Crypto.CertificateSubjectRdnSelector(rdnList);
                case CryptoProviderType.Microsoft:
                    return new KSI.Crypto.Microsoft.Crypto.CertificateSubjectRdnSelector(rdnList);
                default:
                    return null;
            }
        }

        public static ICertificateSubjectRdnSelector CreateCertificateSubjectRdnSelector(string subjectDn)
        {
            switch (ProviderType)
            {
                case CryptoProviderType.BouncyCastle:
                    return new KSI.Crypto.BouncyCastle.Crypto.CertificateSubjectRdnSelector(subjectDn);
                case CryptoProviderType.Microsoft:
                    return new KSI.Crypto.Microsoft.Crypto.CertificateSubjectRdnSelector(subjectDn);
                default:
                    return null;
            }
        }
    }
}