using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     This rule verifies input hash for aggregation chain. If RFC3161 record is present then document hash is first
    ///     hashed to aggregation input hash and is then compared. Otherwise document hash is compared directly to input hash.
    /// </summary>
    public sealed class AggregationChainInputHashVerificationRule : VerificationRule
    {
        /// <summary>
        /// Rule name
        /// </summary>
        public const string RuleName = "AggregationChainInputHashVerificationRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            IKsiSignature signature = context.Signature;
            DataHash inputHash = context.DocumentHash;
            if (signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = signature.GetAggregationHashChains();
            if (aggregationHashChains == null || aggregationHashChains.Count == 0)
            {
                throw new KsiVerificationException("Aggregation hash chains missing in KSI signature.");
            }

            DataHash aggregationHashChainInputHash = aggregationHashChains[0].InputHash;
            if (signature.IsRfc3161Signature)
            {
                DataHasher hasher = new DataHasher(aggregationHashChainInputHash.Algorithm);
                if (signature.Rfc3161Record == null)
                {
                    throw new KsiVerificationException("No RFC 3161 record in KSI signature.");
                }

                hasher.AddData(signature.Rfc3161Record.GetOutputHash(inputHash).Imprint);
                inputHash = hasher.GetHash();

                return inputHash != aggregationHashChainInputHash ? new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Int01) : new VerificationResult(RuleName, VerificationResultCode.Ok);
            }

            if (inputHash == null)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Ok);
            }

            return inputHash != aggregationHashChainInputHash ? new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Gen01) : new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}