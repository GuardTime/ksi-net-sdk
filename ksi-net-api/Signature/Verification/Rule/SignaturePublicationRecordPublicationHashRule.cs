﻿using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class SignaturePublicationRecordPublicationHashRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Signature cannot be null");
            }

            PublicationRecord publicationRecord = context.Signature.PublicationRecord;
            if (publicationRecord == null)
            {
                return VerificationResult.Ok;
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;

            return publicationRecord.PublicationData.PublicationHash.Value != calendarHashChain.PublicationData.PublicationHash.Value ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}