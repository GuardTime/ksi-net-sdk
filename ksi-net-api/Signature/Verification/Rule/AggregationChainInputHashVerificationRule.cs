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
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            DataHash inputHash = context.DocumentHash;
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(signature, false);
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

                return inputHash != aggregationHashChainInputHash
                    ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int01)
                    : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            if (inputHash == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            return inputHash != aggregationHashChainInputHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Gen01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}