namespace Guardtime.KSI.Signature.Verification.Rule
{
    public abstract class IRule
    {
        public static readonly IRule Empty = new EmptyVerificationRule();

        private IRule _onSuccess;
        private IRule _onFailure;
        private IRule _onNa;

        public IRule NextRule(VerificationResult result)
        {
            switch (result)
            {
                case VerificationResult.Ok:
                    return _onSuccess;
                case VerificationResult.Fail:
                    return _onFailure;
                case VerificationResult.Na:
                    return _onNa;
                default:
                    return null;
            }
        }

        public IRule OnSuccess(IRule onSuccess)
        {
            _onSuccess = onSuccess;
            return this;
        }

        public IRule OnNa(IRule onNa)
        {
            _onNa = onNa;
            return this;
        }

        public IRule OnFailure(IRule onFailure)
        {
            _onFailure = onFailure;
            return this;
        }

        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public abstract VerificationResult Verify(VerificationContext context);

        private class EmptyVerificationRule : IRule
        {
            public override VerificationResult Verify(VerificationContext context)
            {
                return VerificationResult.Ok;
            }

            
        }
    }
}