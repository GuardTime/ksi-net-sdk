using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using NLog;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Verification rule.
    /// </summary>
    public abstract class VerificationRule
    {
        protected static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private VerificationRule _onFailure;
        private VerificationRule _onNa;
        private VerificationRule _onSuccess;

        public string GetRuleName()
        {
            return GetType().Name;
        }

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

        public static void CheckVerificationContext(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }
        }

        /// <summary>
        /// Get KSi signature from verification context
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>KSI signature</returns>
        public static IKsiSignature GetSignature(IVerificationContext context)
        {
            CheckVerificationContext(context);

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            return context.Signature;
        }

        /// <summary>
        ///     Get aggregation hash chain collection from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="canBeEmpty">indicates if aggregation has chain collection can be empty</param>
        /// <returns>aggregation hash chain collection</returns>
        public static ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains(IKsiSignature signature, bool canBeEmpty)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = signature.GetAggregationHashChains();

            if (aggregationHashChains == null || (!canBeEmpty && aggregationHashChains.Count == 0))
            {
                throw new KsiVerificationException("Aggregation hash chains are missing from KSI signature.");
            }

            return aggregationHashChains;
        }

        /// <summary>
        /// Get publications file form verification context
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>publications file</returns>
        public static IPublicationsFile GetPublicationsFile(IVerificationContext context)
        {
            CheckVerificationContext(context);

            if (context.PublicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file in context: null.");
            }

            return context.PublicationsFile;
        }

        /// <summary>
        /// Get calendar has chain from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="allowNullValue">indicates if returning null value is allowed</param>
        /// <returns>calendar hash chain</returns>
        public static CalendarHashChain GetCalendarHashChain(IKsiSignature signature, bool allowNullValue = false)
        {
            CalendarHashChain calendarHashChain = signature.CalendarHashChain;
            if (!allowNullValue && calendarHashChain == null)
            {
                throw new KsiVerificationException("Calendar hash chain is missing from KSI signature.");
            }
            return calendarHashChain;
        }

        /// <summary>
        /// Get calendar authentication record from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>calendar authentication record</returns>
        public static CalendarAuthenticationRecord GetCalendarAuthenticationRecord(IKsiSignature signature)
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new KsiVerificationException("Invalid calendar authentication record in signature: null.");
            }
            return calendarAuthenticationRecord;
        }

        /// <summary>
        /// Get publication record from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>publication record</returns>
        public static PublicationRecord GetPublicationRecord(IKsiSignature signature)
        {
            PublicationRecord publicationRecord = signature.PublicationRecord;

            if (publicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publications record in KSI signature: null.");
            }

            return publicationRecord;
        }

        /// <summary>
        /// Get user publication from verification context
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>user publication</returns>
        public static PublicationData GetUserPublication(IVerificationContext context)
        {
            CheckVerificationContext(context);

            PublicationData userPublication = context.UserPublication;

            if (context.UserPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null.");
            }
            return userPublication;
        }
    }
}