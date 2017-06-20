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
using Guardtime.KSI.Exceptions;
using Org.BouncyCastle.X509;

namespace Guardtime.KSI.Crypto.BouncyCastle.Crypto
{
    /// <summary>
    /// Class for verifying that a certificate was valid on given time
    /// </summary>
    public class CertificateTimeVerifier
    {
        /// <summary>
        /// Verify that given certificate was valid on given time
        /// </summary>
        /// <param name="certificate">certificate</param>
        /// <param name="time">time to check certificate validity against</param>
        public static void Verify(X509Certificate certificate, ulong? time)
        {
            if (time.HasValue)
            {
                DateTime signTime = Utils.Util.ConvertUnixTimeToDateTime(time.Value);
                if (certificate.NotBefore > signTime || certificate.NotAfter < signTime)
                {
                    throw new PkiVerificationFailedCertNotValidException(string.Format("Certificate not valid at {0}.", signTime));
                }
            }
        }
    }
}