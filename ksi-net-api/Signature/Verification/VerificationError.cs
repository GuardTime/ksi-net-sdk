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

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    ///     Verification error implementation.
    /// </summary>
    public sealed class VerificationError
    {
        /// <summary>
        ///     Wrong document error.
        /// </summary>
        public static readonly VerificationError Gen01 = new VerificationError("GEN-1", "Wrong document");

        /// <summary>
        ///     Verification inconclusive error.
        /// </summary>
        public static readonly VerificationError Gen02 = new VerificationError("GEN-2", "Verification inconclusive");

        /// <summary>
        ///     Inconsistent aggregation hash chains error.
        /// </summary>
        public static readonly VerificationError Int01 = new VerificationError("INT-01", "Inconsistent aggregation hash chains");

        /// <summary>
        ///     Inconsistent aggregation hash chain aggregation times error.
        /// </summary>
        public static readonly VerificationError Int02 = new VerificationError("INT-02", "Inconsistent aggregation hash chain aggregation times");

        /// <summary>
        ///     Calendar hash chain input hash mismatch error.
        /// </summary>
        public static readonly VerificationError Int03 = new VerificationError("INT-03", "Calendar hash chain input hash mismatch");

        /// <summary>
        ///     Calendar hash chain aggregation time mismatch error.
        /// </summary>
        public static readonly VerificationError Int04 = new VerificationError("INT-04", "Calendar hash chain aggregation time mismatch");

        /// <summary>
        ///     Calendar hash chain shape inconsistent with aggregation time error.
        /// </summary>
        public static readonly VerificationError Int05 = new VerificationError("INT-05", "Calendar hash chain shape inconsistent with aggregation time");

        /// <summary>
        ///     Calendar hash chain time inconsistent with calendar authentication record time error.
        /// </summary>
        public static readonly VerificationError Int06 = new VerificationError("INT-06", "Calendar hash chain time inconsistent with calendar authentication record time");

        /// <summary>
        ///     Calendar hash chain time inconsistent with publication time error.
        /// </summary>
        public static readonly VerificationError Int07 = new VerificationError("INT-07", "Calendar hash chain time inconsistent with publication time");

        /// <summary>
        ///     Calendar hash chain root hash is inconsistent with calendar auth record input hash error.
        /// </summary>
        public static readonly VerificationError Int08 = new VerificationError("INT-08", "Calendar hash chain root hash is inconsistent with calendar auth record input hash");

        /// <summary>
        ///     Calendar hash chain root hash is inconsistent with published hash value error.
        /// </summary>
        public static readonly VerificationError Int09 = new VerificationError("INT-09", "Calendar hash chain root hash is inconsistent with published hash value");

        /// <summary>
        ///     Aggregation hash chain chain index mismatch error.
        /// </summary>
        public static readonly VerificationError Int10 = new VerificationError("INT-10", "Aggregation hash chain chain index mismatch");

        /// <summary>
        ///     The meta-data record in the aggregation hash chain may not be trusted error.
        /// </summary>
        public static readonly VerificationError Int11 = new VerificationError("INT-11", "The meta-data record in the aggregation hash chain may not be trusted");

        /// <summary>
        ///     Inconsistent chain indexes error.
        /// </summary>
        public static readonly VerificationError Int12 = new VerificationError("INT-12", "Inconsistent chain indexes");

        /// <summary>
        ///     Extender response calendar root hash mismatch error.
        /// </summary>
        public static readonly VerificationError Pub01 = new VerificationError("PUB-01", "Extender response calendar root hash mismatch");

        /// <summary>
        ///     Extender response inconsistent error.
        /// </summary>
        public static readonly VerificationError Pub02 = new VerificationError("PUB-02", "Extender response inconsistent");

        /// <summary>
        ///     Extender response input hash mismatch error.
        /// </summary>
        public static readonly VerificationError Pub03 = new VerificationError("PUB-03", "Extender response input hash mismatch");

        /// <summary>
        ///     Publication record hash and user provided publication hash mismatch error.
        /// </summary>
        public static readonly VerificationError Pub04 = new VerificationError("PUB-04", "Publication record hash and user provided publication hash mismatch");

        /// <summary>
        ///     Publication record hash and publications file publication hash mismatch error.
        /// </summary>
        public static readonly VerificationError Pub05 = new VerificationError("PUB-05", "Publication record hash and publications file publication hash mismatch");

        /// <summary>
        ///     Certificate not found error.
        /// </summary>
        public static readonly VerificationError Key01 = new VerificationError("KEY-01", "Certificate not found");

        /// <summary>
        ///     PKI signature not verified with certificate error.
        /// </summary>
        public static readonly VerificationError Key02 = new VerificationError("KEY-02", "PKI signature not verified with certificate");

        /// <summary>
        ///     Calendar root hash mismatch error between signature and calendar database chain.
        /// </summary>
        public static readonly VerificationError Cal01 = new VerificationError("CAL-01", "Calendar root hash mismatch between signature and calendar database chain");

        /// <summary>
        ///     Aggregation hash chain root hash and calendar database hash chain input hash mismatch error.
        /// </summary>
        public static readonly VerificationError Cal02 = new VerificationError("CAL-02", "Aggregation hash chain root hash and calendar database hash chain input hash mismatch");

        /// <summary>
        ///     Aggregation time mismatch error.
        /// </summary>
        public static readonly VerificationError Cal03 = new VerificationError("CAL-03", "Aggregation time mismatch");

        /// <summary>
        ///     Calendar hash chain right links are inconsistent error.
        /// </summary>
        public static readonly VerificationError Cal04 = new VerificationError("CAL-04", "Calendar hash chain right links are inconsistent");

        private VerificationError(string code, string message)
        {
            Code = code;
            Message = message;
        }

        /// <summary>
        ///     Get verification error code.
        /// </summary>
        public string Code { get; }

        /// <summary>
        ///     Get verification error message.
        /// </summary>
        public string Message { get; }

        /// <summary>
        ///  Returns a string that represents the current object.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return string.Format("{0}: {1}", Code, Message);
        }
    }
}