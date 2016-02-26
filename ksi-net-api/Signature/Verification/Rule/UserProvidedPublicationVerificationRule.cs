/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using NLog;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication equals to publication in KSI signature.
    /// </summary>
    public sealed class UserProvidedPublicationVerificationRule : VerificationRule
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            PublicationData userPublication = GetUserPublication(context);
            PublicationData signaturePublication = GetPublicationRecord(signature).PublicationData;

            if (userPublication.PublicationTime == signaturePublication.PublicationTime && userPublication.PublicationHash == signaturePublication.PublicationHash)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            Logger.Debug("User provided publication does not equal to signature publication.{0}User provided publication:{1}{2}{3}Signature publication:{4}{5}",
                Environment.NewLine,
                Environment.NewLine,
                userPublication,
                Environment.NewLine,
                Environment.NewLine,
                signaturePublication);

            return new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}