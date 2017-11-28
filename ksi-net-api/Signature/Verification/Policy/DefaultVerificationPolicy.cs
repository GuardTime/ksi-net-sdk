/*
 * Copyright 2013-2017 Guardtime, Inc.
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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Recommended default policy for verifying KSI signatures.
    /// When verifying a signature at first it is verified against given document hash and publications file. 
    /// If suitable publication is not found in publications file then the KSI signature is extended (if extending is allowed).
    /// If extending is not allowed or not yet possible then key based verification is done.
    /// </summary>
    public class DefaultVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create default verification policy.
        /// </summary>
        public DefaultVerificationPolicy()
        {
            FirstRule = new PublicationBasedVerificationPolicy()
                .OnNa(new KeyBasedVerificationPolicy(true));
        }

        /// <summary>
        /// Verify KSI signature with given context and policy.
        /// Following properties could be set in the context:
        ///  - KSI signature: signature to be verified (mandatory)
        ///  - Document hash (optional)
        ///  - Document hash level (optional)
        ///  - Publications file (mandatory)
        ///  - IsExtendingAllowed: set true if extending should be allowed
        ///  - KSI service (optional: needed when IsExtendingAllowed is set true)
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override VerificationResult Verify(IVerificationContext context)
        {
            return base.Verify(context);
        }

        /// <summary>
        /// Verify given KSI signature.
        /// At first the signature is verified against given publications file. 
        /// If suitable publication is not found in publications file then key based verification is done.
        /// </summary>
        /// <param name="ksiSignature">KSI signature to be verified.</param>
        /// <param name="publicationsFile">Publications file.</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(IKsiSignature ksiSignature, IPublicationsFile publicationsFile)
        {
            if (ksiSignature == null)
            {
                throw new ArgumentNullException(nameof(ksiSignature));
            }

            if (publicationsFile == null)
            {
                throw new ArgumentNullException(nameof(publicationsFile));
            }

            return base.Verify(new VerificationContext()
            {
                Signature = ksiSignature,
                PublicationsFile = publicationsFile,
            });
        }

        /// <summary>
        /// Verify given KSI signature.
        /// At first the signature is verified against given document hash and publications file. 
        /// If suitable publication is not found in publications file then key based verification is done.
        /// </summary>
        /// <param name="ksiSignature">KSI signature to be verified.</param>
        /// <param name="documentHash">Document hash</param>
        /// <param name="publicationsFile">Publications file.</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(IKsiSignature ksiSignature, DataHash documentHash, IPublicationsFile publicationsFile)
        {
            if (ksiSignature == null)
            {
                throw new ArgumentNullException(nameof(ksiSignature));
            }

            if (documentHash == null)
            {
                throw new ArgumentNullException(nameof(documentHash));
            }

            if (publicationsFile == null)
            {
                throw new ArgumentNullException(nameof(publicationsFile));
            }

            return base.Verify(new VerificationContext()
            {
                Signature = ksiSignature,
                DocumentHash = documentHash,
                PublicationsFile = publicationsFile,
            });
        }

        /// <summary>
        /// Verify given KSI signature.
        /// At first the signature is verified against given publications file. Publications file is downloaded using given KSI service.
        /// If suitable publication is not found in publications file then the KSI signature is extended.
        /// If extending is not yet possible then key based verification is done.
        /// </summary>
        /// <param name="ksiSignature">KSI signature to be verified.</param>
        /// <param name="ksiService">KSI services for downloading publications file and extending KSI signature if needed.</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(IKsiSignature ksiSignature, IKsiService ksiService)
        {
            if (ksiSignature == null)
            {
                throw new ArgumentNullException(nameof(ksiSignature));
            }

            if (ksiService == null)
            {
                throw new ArgumentNullException(nameof(ksiService));
            }

            return base.Verify(new VerificationContext()
            {
                Signature = ksiSignature,
                PublicationsFile = ksiService.GetPublicationsFile(),
                KsiService = ksiService,
                IsExtendingAllowed = true
            });
        }

        /// <summary>
        /// Verify given KSI signature.
        /// At first the signature is verified against given document hash and publications file. Publications file is downloaded using given KSI service.
        /// If suitable publication is not found in publications file then the KSI signature is extended.
        /// If extending is not yet possible then key based verification is done.
        /// </summary>
        /// <param name="ksiSignature">KSI signature to be verified.</param>
        /// <param name="documentHash">Document hash</param>
        /// <param name="ksiService">KSI services for downloading publications file and extending KSI signature if needed.</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(IKsiSignature ksiSignature, DataHash documentHash, IKsiService ksiService)
        {
            if (ksiSignature == null)
            {
                throw new ArgumentNullException(nameof(ksiSignature));
            }

            if (documentHash == null)
            {
                throw new ArgumentNullException(nameof(documentHash));
            }

            if (ksiService == null)
            {
                throw new ArgumentNullException(nameof(ksiService));
            }

            return base.Verify(new VerificationContext()
            {
                Signature = ksiSignature,
                DocumentHash = documentHash,
                PublicationsFile = ksiService.GetPublicationsFile(),
                KsiService = ksiService,
                IsExtendingAllowed = true
            });
        }
    }
}