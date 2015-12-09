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
        private readonly IList<VerificationResult> _childResults = new List<VerificationResult>();

        /// <summary>
        ///     Create new rule verification result from list.
        /// </summary>
        /// <param name="ruleName">verification rule name</param>
        /// <param name="resultList">verification result list</param>
        public VerificationResult(string ruleName, IList<VerificationResult> resultList)
            : this(ruleName, GetVerificationResultCodeFromList(resultList))
        {
            for (int i = 0; i < resultList.Count; i++)
            {
                _childResults.Add(resultList[i]);
            }
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

            for (int i = 0; i < _childResults.Count; i++)
            {
                builder.AppendLine(Util.TabPrefixString(_childResults[i].ToString()));
            }
            return builder.ToString();
        }
    }
}