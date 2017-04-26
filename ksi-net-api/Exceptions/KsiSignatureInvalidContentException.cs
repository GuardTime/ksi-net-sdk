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
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     KSI signature invalid content exception. Used when creating signature and signature automatic verification fails.
    /// </summary>
    [Serializable]
    public class KsiSignatureInvalidContentException : Exception
    {
        /// <summary>
        ///     Create new KSI signature invalid content exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="signature">The signature the exception is associated with</param>
        /// <param name="verificationResult">Verficiation result</param>
        public KsiSignatureInvalidContentException(string message, IKsiSignature signature, VerificationResult verificationResult) : base(message)
        {
            Signature = signature;
            VerificationResult = verificationResult;
        }

        /// <summary>
        ///     Create new KSI signature invalid content exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        /// <param name="signature">The signature the exception is associated with</param>
        /// <param name="verificationResult">Verficiation result</param>
        public KsiSignatureInvalidContentException(string message, Exception innerException, IKsiSignature signature, VerificationResult verificationResult)
            : base(message, innerException)
        {
            Signature = signature;
            VerificationResult = verificationResult;
        }

        /// <summary>
        /// The signature the exception is associated with
        /// </summary>
        public IKsiSignature Signature { get; }

        /// <summary>
        /// Verificiation result
        /// </summary>
        public VerificationResult VerificationResult { get; }
    }
}