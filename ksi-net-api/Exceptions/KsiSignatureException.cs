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
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     KSI signature exception
    /// </summary>
    [Serializable]
    public class KsiSignatureException : Exception
    {
        /// <summary>
        ///     Create new KSI signature exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="signature">The signature the exception is associated to</param>
        public KsiSignatureException(string message, IKsiSignature signature) : base(message)
        {
            Signature = signature;
        }

        /// <summary>
        ///     Create new KSI signature exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        /// <param name="signature">The signature the exception is associated to</param>
        public KsiSignatureException(string message, Exception innerException, IKsiSignature signature) : base(message, innerException)
        {
            Signature = signature;
        }

        /// <summary>
        /// The signature the exception is associated to
        /// </summary>
        public IKsiSignature Signature { get; set; }
    }
}