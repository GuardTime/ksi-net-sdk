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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI
{
    /// <summary>
    ///     Simple implementation of KSI services.
    /// </summary>
    public class Ksi
    {
        private readonly IKsiService _ksiService;

        /// <summary>
        ///     Create new KSI instance.
        /// </summary>
        /// <param name="ksiService">KSI service</param>
        public Ksi(IKsiService ksiService)
        {
            if (ksiService == null)
            {
                throw new KsiException("KSI service cannot be null.");
            }
            _ksiService = ksiService;
        }

        /// <summary>
        ///     Sign document hash.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
        /// DataHash hash;
        /// KsiService ksiService;
        /// 
        /// IKsiSignature signature = ksiService.Sign(hash);
        /// </code>
        ///     </example>
        /// </summary>
        /// <param name="hash">document hash</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Sign(DataHash hash)
        {
            if (hash == null)
            {
                throw new KsiException("Document hash cannot be null.");
            }

            return _ksiService.Sign(hash);
        }

        /// <summary>
        ///     Extend signature to calendar head.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
        /// KsiService ksiService;
        /// IKsiSignature signature;
        /// IPublicationsFile publicationsFile.
        /// 
        /// CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime, publicationsFile.GetLatestPublication().PublicationData.PublicationTime);
        /// IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
        /// </code>
        ///     </example>
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature ExtendToHead(IKsiSignature signature)
        {
            return Extend(signature, GetPublicationsFile().GetLatestPublication());
        }

        /// <summary>
        ///     Extend signature to publication.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
        /// KsiService ksiService;
        /// IKsiSignature signature;
        /// PublicationRecord publicationRecord;
        /// 
        /// CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
        /// IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
        /// </code>
        ///     </example>
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature, PublicationRecordInPublicationFile publicationRecord)
        {
            if (signature == null)
            {
                throw new KsiException("KSI signature cannot be null.");
            }

            if (publicationRecord == null)
            {
                throw new KsiException("Publication record cannot be null.");
            }

            CalendarHashChain calendarHashChain = _ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
            return signature.Extend(calendarHashChain, publicationRecord);
        }

        /// <summary>
        ///     Extend signature to publication.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
        /// KsiService ksiService;
        /// IKsiSignature signature;
        /// PublicationRecord publicationRecord;
        /// 
        /// CalendarHashChain calendarHashChain = ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
        /// IKsiSignature extendedSignature = signature.Extend(calendarHashChain, publicationRecord);
        /// </code>
        ///     </example>
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature, PublicationRecordInSignature publicationRecord)
        {
            if (signature == null)
            {
                throw new KsiException("KSI signature cannot be null.");
            }

            if (publicationRecord == null)
            {
                throw new KsiException("Publication record cannot be null.");
            }

            CalendarHashChain calendarHashChain = _ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
            return signature.Extend(calendarHashChain, publicationRecord);
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationData">publication data</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature, PublicationData publicationData)
        {
            if (signature == null)
            {
                throw new KsiException("KSI signature cannot be null.");
            }

            if (publicationData == null)
            {
                throw new KsiException("Publication data cannot be null.");
            }

            PublicationRecordInPublicationFile publicationRecord = GetPublicationsFile().GetNearestPublicationRecord(publicationData.PublicationTime);
            return Extend(signature, publicationRecord);
        }

        /// <summary>
        ///     Extend signature to closest publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new KsiException("KSI signature cannot be null.");
            }
            PublicationRecordInPublicationFile publicationRecord = GetPublicationsFile().GetNearestPublicationRecord(signature.AggregationTime);
            return Extend(signature, publicationRecord);
        }

        /// <summary>
        ///     Get publications file.
        ///     <example>
        ///         Equals to following code
        ///         <code>
        /// KsiProvider.SetCryptoProvider(new MicrosoftCryptoProvider()); 
        /// KsiService ksiService;
        /// 
        /// IPublicationsFile publicationsFile = ksiService.GetPublicationsFile();
        /// </code>
        ///     </example>
        /// </summary>
        /// <returns>publications file</returns>
        public IPublicationsFile GetPublicationsFile()
        {
            // TODO: cache result?
            IPublicationsFile publicationsFile = _ksiService.GetPublicationsFile();
            if (publicationsFile == null)
            {
                throw new KsiException("Publications file cannot be null.");
            }

            return publicationsFile;
        }

        /// <summary>
        ///     Verify keyless signature.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <param name="policy">verification rule</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(IVerificationContext context, VerificationRule policy)
        {
            if (policy == null)
            {
                throw new KsiException("Invalid verification rule: null.");
            }

            return policy.Verify(context);
        }
    }
}