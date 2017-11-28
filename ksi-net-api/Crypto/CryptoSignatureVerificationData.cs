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

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// Data to be used when verifying a crypo signature.
    /// </summary>
    public class CryptoSignatureVerificationData
    {
        /// <summary>
        /// Trust anchor certificate bytes
        /// </summary>
        public byte[] CertificateBytes { get; }

        /// <summary>
        /// Time of signing. If the time is given then it will be used for checking if certificate was valid at the given time.
        /// </summary>
        public ulong? SignTime { get; }

        /// <summary>
        /// Create crypto signature verification data instance
        /// </summary>
        /// <param name="certificate">Trust anchor certificate bytes</param>
        /// <param name="signTime">Time of signing. If the time is given then it will be used for checking if certificate was valid at the given time.</param>
        public CryptoSignatureVerificationData(byte[] certificate, ulong? signTime = null)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            CertificateBytes = certificate;
            SignTime = signTime;
        }
    }
}