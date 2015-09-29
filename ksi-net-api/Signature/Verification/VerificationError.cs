namespace Guardtime.KSI.Signature.Verification
{
    public sealed class VerificationError
    {
        public static readonly VerificationError Gen01 = new VerificationError("GEN-1", "Wrong document");
        public static readonly VerificationError Gen02 = new VerificationError("GEN-2", "Verification inconclusive");
        public static readonly VerificationError Int01 = new VerificationError("INT-01", "Inconsistent aggregation hash chains");
        public static readonly VerificationError Int02 = new VerificationError("INT-02", "Inconsistent aggregation hash chain aggregation times");
        public static readonly VerificationError Int03 = new VerificationError("INT-03", "Calendar hash chain input hash mismatch");
        public static readonly VerificationError Int04 = new VerificationError("INT-04", "Calendar hash chain aggregation time mismatch");
        public static readonly VerificationError Int05 = new VerificationError("INT-05", "Calendar hash chain shape inconsistent with aggregation time");
        public static readonly VerificationError Int06 = new VerificationError("INT-06", "Calendar hash chain time inconsistent with calendar auth record time");
        public static readonly VerificationError Int07 = new VerificationError("INT-07", "Calendar hash chain time inconsistent with publication time");
        public static readonly VerificationError Int08 = new VerificationError("INT-08", "Calendar hash chain root has inconsistent with calendar auth record time");
        public static readonly VerificationError Int09 = new VerificationError("INT-09", "Calendar hash chain root has inconsistent with publication time");
        public static readonly VerificationError Pub01 = new VerificationError("PUB-01", "Extender response calendar root hash mismatch");
        public static readonly VerificationError Pub02 = new VerificationError("PUB-02", "Extender response inconsistent");
        public static readonly VerificationError Pub03 = new VerificationError("PUB-03", "Extender response input hash mismatch");
        public static readonly VerificationError Key01 = new VerificationError("KEY-01", "Certificate not found");
        public static readonly VerificationError Key02 = new VerificationError("KEY-02", "PKI signature not verified with certificate");
        public static readonly VerificationError Cal01 = new VerificationError("CAL-01", "Calendar root hash mismatch");
        public static readonly VerificationError Cal02 = new VerificationError("CAL-02", "Aggregation hash chain root hash and calendar hash chain input hash mismatch");
        public static readonly VerificationError Cal03 = new VerificationError("CAL-03", "Aggregation time mismatch");
        public static readonly VerificationError Cal04 = new VerificationError("CAL-04", "Aggregation hash chain right links are inconsistent");

        private readonly string _code;
        private readonly string _message;

        private VerificationError(string code, string message)
        {
            _code = code;
            _message = message;
        }

        public string Code
        {
            get { return _code; }
        }

        public string Message
        {
            get
            {
                return _message;
            }
        }
    }
}