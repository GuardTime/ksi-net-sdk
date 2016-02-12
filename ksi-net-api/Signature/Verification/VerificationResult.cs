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
using System.Collections.Generic;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    ///     Rule verification result.
    /// </summary>
    public class VerificationResult
    {
        private readonly List<VerificationResult> _childResults = new List<VerificationResult>();

        /// <summary>
        ///     Create new rule verification result from list.
        /// </summary>
        /// <param name="ruleName">verification rule name</param>
        /// <param name="resultList">verification result list</param>
        public VerificationResult(string ruleName, IList<VerificationResult> resultList)
            : this(ruleName, GetVerificationResultCodeFromList(resultList))
        {
            _childResults.AddRange(resultList);
        }

        /// <summary>
        ///     Create new verification result instance.
        /// </summary>
        /// <param name="ruleName">verification rule name</param>
        /// <param name="resultCode">verification result code</param>
        public VerificationResult(string ruleName, VerificationResultCode resultCode) : this(ruleName, resultCode, null)
        {
        }

        /// <summary>
        ///     Create new verification result instance.
        /// </summary>
        /// <param name="ruleName">verification rule name</param>
        /// <param name="resultCode">verification result code</param>
        /// <param name="error">verification error</param>
        public VerificationResult(string ruleName, VerificationResultCode resultCode, VerificationError error)
        {
            ResultCode = resultCode;
            RuleName = ruleName;
            VerificationError = error;
        }

        /// <summary>
        ///     Get verification rule name.
        /// </summary>
        public string RuleName { get; }

        /// <summary>
        ///     Get verification result code.
        /// </summary>
        public VerificationResultCode ResultCode { get; }

        /// <summary>
        ///     Get verification error if exists, otherwise null.
        /// </summary>
        public VerificationError VerificationError { get; }

        private static VerificationResultCode GetVerificationResultCodeFromList(IList<VerificationResult> resultList)
        {
            if (resultList == null || resultList.Count == 0)
            {
                throw new KsiException("Invalid result list, no elements found.");
            }

            return resultList[resultList.Count - 1].ResultCode;
        }

        /// <summary>
        ///     Returns a string that represents the current object.
        /// </summary>
        /// <returns>
        ///     A string that represents the current object.
        /// </returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(RuleName).Append(": ");
            builder.Append(ResultCode);

            if (_childResults.Count > 0)
            {
                builder.AppendLine();
            }

            foreach (VerificationResult childResult in _childResults)
            {
                builder.AppendLine(Util.TabPrefixString(childResult.ToString()));
            }
            return builder.ToString();
        }
    }
}