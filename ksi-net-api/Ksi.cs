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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;

namespace Guardtime.KSI
{
    /// <summary>
    ///     Simple implementation of KSI services.
    /// </summary>
    public class Ksi
    {
        private readonly IKsiService _ksiService;
        private readonly IKsiSignatureFactory _ksiSignatureFactoryForExtending;
        private IPublicationsFile _publicationsFile;
        private DateTime _publicationsFileLoadTime;

        /// <summary>
        ///     Create new KSI instance.
        /// </summary>
        /// <param name="ksiService">KSI service</param>
        /// <param name="ksiSignatureFactoryForExtending">Signature factory to be used for creating an extended signature</param>
        public Ksi(IKsiService ksiService, IKsiSignatureFactory ksiSignatureFactoryForExtending = null)
        {
            if (ksiService == null)
            {
                throw new ArgumentNullException(nameof(ksiService));
            }

            _ksiService = ksiService;
            _ksiSignatureFactoryForExtending = ksiSignatureFactoryForExtending ?? new KsiSignatureFactory();
        }

        /// <summary>
        /// Sign document hash.
        /// </summary>
        /// <param name="hash">document hash</param>
        /// <param name="level">The document hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Sign(DataHash hash, uint level = 0)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            return _ksiService.Sign(hash, level);
        }

        /// <summary>
        /// Sign document hash.
        /// </summary>
        /// <param name="stream">Stream containing document bytes</param>
        /// <param name="level">The document hash node level value in the aggregation tree</param>
        /// <returns></returns>
        public IKsiSignature Sign(Stream stream, uint level = 0)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            IDataHasher dataHasher = KsiProvider.CreateDataHasher();
            dataHasher.AddData(stream);
            return _ksiService.Sign(dataHasher.GetHash(), level);
        }

        /// <summary>
        /// Sign document hash.
        /// </summary>
        /// <param name="documentBytes">Document bytes</param>
        /// <param name="level">The document hash node level value in the aggregation tree</param>
        /// <returns></returns>
        public IKsiSignature Sign(byte[] documentBytes, uint level = 0)
        {
            if (documentBytes == null)
            {
                throw new ArgumentNullException(nameof(documentBytes));
            }

            IDataHasher dataHasher = KsiProvider.CreateDataHasher();
            dataHasher.AddData(documentBytes);
            return _ksiService.Sign(dataHasher.GetHash(), level);
        }

        /// <summary>
        /// Get additional aggregator configuration data
        /// </summary>
        /// <returns>Aggregator configuration data</returns>
        public AggregatorConfig GetAggregatorConfig()
        {
            return _ksiService.GetAggregatorConfig();
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature, PublicationRecordInPublicationFile publicationRecord)
        {
            if (publicationRecord == null)
            {
                throw new ArgumentNullException(nameof(publicationRecord));
            }

            return Extend(signature, publicationRecord.ConvertToPublicationRecordInSignature());
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature, PublicationRecordInSignature publicationRecord)
        {
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (publicationRecord == null)
            {
                throw new ArgumentNullException(nameof(publicationRecord));
            }

            CalendarHashChain calendarHashChain = _ksiService.Extend(signature.AggregationTime, publicationRecord.PublicationData.PublicationTime);
            return signature.Extend(calendarHashChain, publicationRecord, _ksiSignatureFactoryForExtending);
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationData">publication data</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature, PublicationData publicationData)
        {
            if (publicationData == null)
            {
                throw new ArgumentNullException(nameof(publicationData));
            }

            return Extend(signature, new PublicationRecordInSignature(false, false, publicationData));
        }

        /// <summary>
        ///     Extend signature to nearest publication record in publications file subsequent to signature aggregation time.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            PublicationRecordInPublicationFile publicationRecord = GetPublicationsFile().GetNearestPublicationRecord(signature.AggregationTime);

            if (publicationRecord == null)
            {
                throw new KsiException("No suitable publication yet.");
            }

            return Extend(signature, publicationRecord);
        }

        /// <summary>
        /// Get additional extender configuration data
        /// </summary>
        /// <returns>Extender configuration data</returns>
        public ExtenderConfig GetExtenderConfig()
        {
            return _ksiService.GetExtenderConfig();
        }

        /// <summary>
        ///     Get publications file.
        /// </summary>
        /// <returns>publications file</returns>
        public IPublicationsFile GetPublicationsFile()
        {
            if (_publicationsFileLoadTime > DateTime.Now.AddHours(-1) && _publicationsFile != null)
            {
                return _publicationsFile;
            }

            _publicationsFile = _ksiService.GetPublicationsFile();

            if (_publicationsFile == null)
            {
                throw new KsiException("Invalid publications file: null.");
            }

            _publicationsFileLoadTime = DateTime.Now;

            return _publicationsFile;
        }

        /// <summary>
        /// Verify KSI signature using verification policy and context.
        /// If context indicates that extending is allowed but KsiService is not included then KsiService is added automatically.
        /// </summary>
        /// <param name="policy">Verification policy</param>
        /// <param name="context">Verification context. If context indicates that extending is allowed but KsiService is not included then KsiService is added automatically.</param>
        /// <returns></returns>
        public VerificationResult Verify(VerificationPolicy policy, IVerificationContext context)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.IsExtendingAllowed && context.KsiService == null)
            {
                context.KsiService = _ksiService;
            }

            return policy.Verify(context);
        }

        /// <summary>
        /// Verify KSI signature using DefaultVerificationPolicy with publications file. Extending not allowed.
        /// </summary>
        /// <param name="ksiSignature">KSI signature to be verified.</param>
        /// <param name="documentHash">Document hash</param>
        /// <param name="publicationsFile">Publications file.</param>
        /// <returns></returns>
        public VerificationResult Verify(IKsiSignature ksiSignature, DataHash documentHash, IPublicationsFile publicationsFile)
        {
            return new DefaultVerificationPolicy().Verify(ksiSignature, documentHash, publicationsFile);
        }

        /// <summary>
        /// Verify KSI signature using DefaultVerificationPolicy with extending allowed.
        /// </summary>
        /// <param name="ksiSignature">KSI signature to be verified.</param>
        /// <param name="documentHash">Document hash</param>
        /// <returns></returns>
        public VerificationResult Verify(IKsiSignature ksiSignature, DataHash documentHash = null)
        {
            return new DefaultVerificationPolicy().Verify(ksiSignature, documentHash, _ksiService);
        }
    }
}