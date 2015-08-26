using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Signature.Verification
{
    public interface IRule
    {
        VerificationResult Verify(VerificationContext context);
    }
}
