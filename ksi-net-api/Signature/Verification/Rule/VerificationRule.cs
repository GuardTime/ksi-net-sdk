namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Verification rule.
    /// </summary>
    public abstract class VerificationRule
    {
        /// <summary>
        ///     Return empty verification rule.
        /// </summary>
        public static readonly VerificationRule Empty = new EmptyVerificationVerificationRule();

        private VerificationRule _onFailure;
        private VerificationRule _onNa;

        private VerificationRule _onSuccess;

        /// <summary>
        ///     Get next rule based on verification result.
        /// </summary>
        /// <param name="resultCode">verification result</param>
        /// <returns>next verification rule</returns>
        public VerificationRule NextRule(VerificationResultCode resultCode)
        {
            switch (resultCode)
            {
                case VerificationResultCode.Ok:
                    return _onSuccess;
                case VerificationResultCode.Fail:
                    return _onFailure;
                case VerificationResultCode.Na:
                    return _onNa;
                default:
                    return null;
            }
        }

        /// <summary>
        ///     Set next verification rule on success.
        /// </summary>
        /// <param name="onSuccess">next verification rule on success</param>
        /// <returns>current verification rule</returns>
        public VerificationRule OnSuccess(VerificationRule onSuccess)
        {
            _onSuccess = onSuccess;
            return this;
        }

        /// <summary>
        ///     Set next verification rule on na status.
        /// </summary>
        /// <param name="onNa">next verification rule on na status</param>
        /// <returns>current verification rule</returns>
        public VerificationRule OnNa(VerificationRule onNa)
        {
            _onNa = onNa;
            return this;
        }

        /// <summary>
        ///     Set next verification rule on failure.
        /// </summary>
        /// <param name="onFailure">next verification rule on failure</param>
        /// <returns>current verification rule</returns>
        public VerificationRule OnFailure(VerificationRule onFailure)
        {
            _onFailure = onFailure;
            return this;
        }

        /// <summary>
        ///     Verify given context with verification rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public abstract VerificationResult Verify(IVerificationContext context);

        private class EmptyVerificationVerificationRule : VerificationRule
        {
            public override VerificationResult Verify(IVerificationContext context)
            {
                return new VerificationResult(string.Empty, VerificationResultCode.Ok);
            }

            public override string ToString()
            {
                return string.Empty;
            }
        }
    }
}