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
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI
{
    /// <summary>
    /// KSI provider.
    /// </summary>
    public class KsiProvider
    {
        private static ICryptoProvider _cryptoProvider;
        private static readonly object Lock = new object();

        /// <summary>
        /// Set crypto provider.
        /// </summary>
        /// <param name="provider"></param>
        public static void SetCryptoProvider(ICryptoProvider provider)
        {
            _cryptoProvider = provider;
        }

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <returns>PKCS#7 verifier</returns>
        public static ICryptoSignatureVerifier CreatePkcs7CryptoSignatureVerifier()
        {
            CheckCryptoProvider();
            return _cryptoProvider.CreatePkcs7CryptoSignatureVerifier();
        }

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <param name="trustStore">trust anchors</param>
        /// <param name="certificateRdnSelector">Certificate subject RDN selector for verifying certificate subject.</param>
        /// <returns>PKCS#7 verifier</returns>
        public static ICryptoSignatureVerifier CreatePkcs7CryptoSignatureVerifier(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            CheckCryptoProvider();
            X509Certificate2Collection trustAnchors = null;

            if (trustStore != null)
            {
                // make certificates loading thread-safe
                lock (Lock)
                {
                    trustStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    trustAnchors = trustStore.Certificates;
                    trustStore.Close();
                }
            }

            return _cryptoProvider.CreatePkcs7CryptoSignatureVerifier(trustAnchors, certificateRdnSelector);
        }

        /// <summary>
        /// Get RSA signature verifier.
        /// </summary>
        /// <param name="algorithm">hash algorithm</param>
        /// <returns>RSA signature verifier</returns>
        public static ICryptoSignatureVerifier CreateRsaCryptoSignatureVerifier(string algorithm)
        {
            CheckCryptoProvider();
            return _cryptoProvider.CreateRsaCryptoSignatureVerifier(algorithm);
        }

        /// <summary>
        /// Get HMAC hasher.
        /// </summary>
        /// <param name="algorithm">HMAC algorithm</param>
        /// <returns></returns>
        public static IHmacHasher CreateHmacHasher(HashAlgorithm algorithm)
        {
            CheckCryptoProvider();
            ValidateHashAlgorithm(algorithm);

            return _cryptoProvider.CreateHmacHasher(algorithm);
        }

        /// <summary>
        /// Get data hasher.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static IDataHasher CreateDataHasher(HashAlgorithm algorithm)
        {
            CheckCryptoProvider();
            ValidateHashAlgorithm(algorithm);

            return _cryptoProvider.CreateDataHasher(algorithm);
        }

        /// <summary>
        /// Get data hasher.
        /// </summary>
        /// <returns></returns>
        public static IDataHasher CreateDataHasher()
        {
            CheckCryptoProvider();

            return _cryptoProvider.CreateDataHasher(HashAlgorithm.Default);
        }

        /// <summary>
        /// Check if crypto provider exists
        /// </summary>
        private static void CheckCryptoProvider()
        {
            if (_cryptoProvider == null)
            {
                throw new KsiException("Crypto provider not set. Please use SetCryptoProvider.");
            }
        }

        /// <summary>
        /// Check if hash algorithm can be used for hashing.
        /// </summary>
        /// <param name="algorithm">Hash algorithm</param>
        private static void ValidateHashAlgorithm(HashAlgorithm algorithm)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            // If an algorithm is given which is not implemented, an illegal argument exception is thrown.
            // The developer must ensure that only implemented algorithms are used.

            if (algorithm.Status == HashAlgorithm.AlgorithmStatus.NotImplemented)
            {
                throw new HashingException("Hash algorithm is not implemented. Algorithm: " + algorithm.Name);
            }
        }
    }
}