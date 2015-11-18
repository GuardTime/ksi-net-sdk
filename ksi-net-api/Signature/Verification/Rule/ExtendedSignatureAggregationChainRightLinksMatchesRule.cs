﻿using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if extended signature aggregation hash chain links are with same structure and right links are equal to
    ///     not extended signature right links.
    /// </summary>
    public sealed class ExtendedSignatureAggregationChainRightLinksMatchesRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            CalendarHashChain extendedCalendarHashChain = context.GetExtendedTimeCalendarHashChain(GetCalendarHashChain(signature).PublicationData.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException("Received invalid extended calendar hash chain from context extension function: null.");
            }

            return !GetCalendarHashChain(signature).AreRightLinksEqual(extendedCalendarHashChain)
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Cal04)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}