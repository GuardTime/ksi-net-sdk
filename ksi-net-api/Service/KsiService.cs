/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;
using NLog;
using HashAlgorithm = Guardtime.KSI.Hashing.HashAlgorithm;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service.
    /// </summary>
    public partial class KsiService : IKsiService
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HashAlgorithm DefaultMacAlgorithm = HashAlgorithm.Sha2256;
        private const PduVersion DefaultPduVersion = PduVersion.v2;

        private readonly IKsiSigningServiceProtocol _signingServiceProtocol;
        private readonly IKsiExtendingServiceProtocol _extendingServiceProtocol;
        private readonly IKsiSignatureFactory _ksiSignatureFactory;
        private readonly IPublicationsFileFactory _publicationsFileFactory;
        private readonly IKsiPublicationsFileServiceProtocol _publicationsFileServiceProtocol;
        private readonly IServiceCredentials _signingServiceCredentials;
        private readonly IServiceCredentials _extendingServiceCredentials;
        private readonly HashAlgorithm _signingMacAlgorithm;
        private readonly HashAlgorithm _extendingMacAlgorithm;

        /// <summary>
        /// Aggregator configuration changed event
        /// </summary>
        public event EventHandler<AggregatorConfigChangedEventArgs> AggregatorConfigChanged;

        /// <summary>
        /// Extender configuration changed event
        /// </summary>
        public event EventHandler<ExtenderConfigChangedEventArgs> ExtenderConfigChanged;

        /// <summary>
        ///     Create KSI service with service protocol and service settings.
        /// </summary>
        /// <param name="signingServiceProtocol">signing service protocol</param>
        /// <param name="signingServiceCredentials">signing service credentials</param>
        /// <param name="extendingServiceProtocol">extending service protocol</param>
        /// <param name="extendingServiceCredentials">extending service credentials</param>
        /// <param name="publicationsFileServiceProtocol">publications file protocol</param>
        /// <param name="publicationsFileFactory">publications file factory</param>
        /// <param name="pduVersion">PDU version</param>
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory,
                          PduVersion pduVersion)
            :
                this(signingServiceProtocol,
                    signingServiceCredentials,
                    extendingServiceProtocol,
                    extendingServiceCredentials,
                    publicationsFileServiceProtocol,
                    publicationsFileFactory,
                    new KsiSignatureFactory(),
                    pduVersion)
        {
        }

        /// <summary>
        ///     Create KSI service with service protocol and service settings.
        /// </summary>
        /// <param name="signingServiceProtocol">signing service protocol</param>
        /// <param name="signingServiceCredentials">signing service credentials</param>
        /// <param name="extendingServiceProtocol">extending service protocol</param>
        /// <param name="extendingServiceCredentials">extending service credentials</param>
        /// <param name="publicationsFileServiceProtocol">publications file protocol</param>
        /// <param name="publicationsFileFactory">publications file factory</param>
        /// <param name="ksiSignatureFactory">KSI signature factory used when creating a KSI signature</param>
        /// <param name="pduVersion">PDU version to be used</param>
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory,
                          IKsiSignatureFactory ksiSignatureFactory = null,
                          PduVersion? pduVersion = null)
        {
            _signingServiceProtocol = signingServiceProtocol;
            _signingServiceCredentials = signingServiceCredentials;
            _extendingServiceProtocol = extendingServiceProtocol;
            _extendingServiceCredentials = extendingServiceCredentials;
            _publicationsFileServiceProtocol = publicationsFileServiceProtocol;
            _publicationsFileFactory = publicationsFileFactory;
            _ksiSignatureFactory = ksiSignatureFactory ?? new KsiSignatureFactory();
            PduVersion = pduVersion ?? DefaultPduVersion;

            _signingMacAlgorithm = _signingServiceCredentials?.MacAlgorithm ?? DefaultMacAlgorithm;
            _extendingMacAlgorithm = _extendingServiceCredentials?.MacAlgorithm ?? DefaultMacAlgorithm;
        }

        private bool IsLegacyPduVersion => PduVersion == PduVersion.v1;

        /// <summary>
        /// PDU format version
        /// </summary>
        public PduVersion PduVersion { get; }

        /// <summary>
        /// Generate new request ID
        /// </summary>
        /// <returns></returns>
        protected virtual ulong GenerateRequestId()
        {
            return Util.GetRandomUnsignedLong();
        }

        private static KsiServiceAsyncResult GetKsiServiceAsyncResult(IAsyncResult asyncResult)
        {
            if (asyncResult == null)
            {
                throw new ArgumentNullException(nameof(asyncResult));
            }

            KsiServiceAsyncResult serviceAsyncResult = asyncResult as KsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid " + nameof(asyncResult) + " type: " + asyncResult.GetType() + "; Expected type: KsiServiceAsyncResult.");
            }
            return serviceAsyncResult;
        }

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        public override string ToString()
        {
            return string.Format("KsiService (signing: {0}; extending: {1}; publications file: {2})", _signingServiceProtocol?.AggregatorAddress,
                _extendingServiceProtocol?.ExtenderAddress,
                _publicationsFileServiceProtocol?.PublicationsFileAddress);
        }

        /// <summary>
        /// Aggregator address (url or ip)
        /// </summary>
        public string AggregatorAddress => _signingServiceProtocol?.AggregatorAddress;

        /// <summary>
        /// Extender address (url or ip)
        /// </summary>
        public string ExtenderAddress => _extendingServiceProtocol?.ExtenderAddress;

        /// <summary>
        /// Publications file url
        /// </summary>
        public string PublicationsFileAddress => _publicationsFileServiceProtocol?.PublicationsFileAddress;
    }
}