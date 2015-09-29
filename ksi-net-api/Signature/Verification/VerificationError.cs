namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    /// Verification error implementation.
    /// </summary>
    public sealed class VerificationError
    {
        /// <summary>
        /// Wrong document error.
        /// </summary>
        public static readonly VerificationError Gen01 = new VerificationError("GEN-1", "Wrong document");
        /// <summary>
        /// Verification inconclusive error.
        /// </summary>
        public static readonly VerificationError Gen02 = new VerificationError("GEN-2", "Verification inconclusive");
        /// <summary>
        /// Inconsistent aggregation hash chains error.
        /// </summary>
        public static readonly VerificationError Int01 = new VerificationError("INT-01", "Inconsistent aggregation hash chains");
        /// <summary>
        /// Inconsistent aggregation hash chain aggregation times error.
        /// </summary>
        public static readonly VerificationError Int02 = new VerificationError("INT-02", "Inconsistent aggregation hash chain aggregation times");
        /// <summary>
        /// Calendar hash chain input hash mismatch error.
        /// </summary>
        public static readonly VerificationError Int03 = new VerificationError("INT-03", "Calendar hash chain input hash mismatch");
        /// <summary>
        /// Calendar hash chain aggregation time mismatch error.
        /// </summary>
        public static readonly VerificationError Int04 = new VerificationError("INT-04", "Calendar hash chain aggregation time mismatch");
        /// <summary>
        /// Calendar hash chain shape inconsistent with aggregation time error.
        /// </summary>
        public static readonly VerificationError Int05 = new VerificationError("INT-05", "Calendar hash chain shape inconsistent with aggregation time");
        /// <summary>
        /// Calendar hash chain time inconsistent with calendar authentication record time error.
        /// </summary>
        public static readonly VerificationError Int06 = new VerificationError("INT-06", "Calendar hash chain time inconsistent with calendar authentication record time");
        /// <summary>
        /// Calendar hash chain time inconsistent with publication time error.
        /// </summary>
        public static readonly VerificationError Int07 = new VerificationError("INT-07", "Calendar hash chain time inconsistent with publication time");
        /// <summary>
        /// Calendar hash chain root has inconsistency with calendar authentication record time error.
        /// </summary>
        public static readonly VerificationError Int08 = new VerificationError("INT-08", "Calendar hash chain root has inconsistency with calendar authentication record time");
        /// <summary>
        /// Calendar hash chain root has inconsistency with publication time error.
        /// </summary>
        public static readonly VerificationError Int09 = new VerificationError("INT-09", "Calendar hash chain root has inconsistency with publication time");
        /// <summary>
        /// Extender response calendar root hash mismatch error.
        /// </summary>
        public static readonly VerificationError Pub01 = new VerificationError("PUB-01", "Extender response calendar root hash mismatch");
        /// <summary>
        /// Extender response inconsistent error.
        /// </summary>
        public static readonly VerificationError Pub02 = new VerificationError("PUB-02", "Extender response inconsistent");
        /// <summary>
        /// Extender response input hash mismatch error.
        /// </summary>
        public static readonly VerificationError Pub03 = new VerificationError("PUB-03", "Extender response input hash mismatch");
        /// <summary>
        /// Certificate not found error.
        /// </summary>
        public static readonly VerificationError Key01 = new VerificationError("KEY-01", "Certificate not found");
        /// <summary>
        /// PKI signature not verified with certificate error.
        /// </summary>
        public static readonly VerificationError Key02 = new VerificationError("KEY-02", "PKI signature not verified with certificate");
        /// <summary>
        /// Calendar root hash mismatch error.
        /// </summary>
        public static readonly VerificationError Cal01 = new VerificationError("CAL-01", "Calendar root hash mismatch");
        /// <summary>
        /// Aggregation hash chain root hash and calendar hash chain input hash mismatch error.
        /// </summary>
        public static readonly VerificationError Cal02 = new VerificationError("CAL-02", "Aggregation hash chain root hash and calendar hash chain input hash mismatch");
        /// <summary>
        /// Aggregation time mismatch error.
        /// </summary>
        public static readonly VerificationError Cal03 = new VerificationError("CAL-03", "Aggregation time mismatch");
        /// <summary>
        /// Aggregation hash chain right links are inconsistent error.
        /// </summary>
        public static readonly VerificationError Cal04 = new VerificationError("CAL-04", "Aggregation hash chain right links are inconsistent");

        private readonly string _code;
        private readonly string _message;

        private VerificationError(string code, string message)
        {
            _code = code;
            _message = message;
        }

        /// <summary>
        /// Get verification error code.
        /// </summary>
        public string Code
        {
            get { return _code; }
        }

        /// <summary>
        /// Get verification error message.
        /// </summary>
        public string Message
        {
            get
            {
                return _message;
            }
        }
    }
}