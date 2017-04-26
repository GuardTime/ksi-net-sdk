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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    ///     Verification context interface.
    /// </summary>
    public interface IVerificationContext
    {
        /// <summary>
        ///     Get document hash.
        /// </summary>
        DataHash DocumentHash { get; set; }

        /// <summary>
        ///     Get signature.
        /// </summary>
        IKsiSignature Signature { get; set; }

        /// <summary>
        ///     Get user publication.
        /// </summary>
        PublicationData UserPublication { get; }

        /// <summary>
        ///     Get KSI service.
        /// </summary>
        IKsiService KsiService { get; }

        /// <summary>
        ///     Is extending allowed.
        /// </summary>
        bool IsExtendingAllowed { get; }

        /// <summary>
        ///     Get publications file.
        /// </summary>
        IPublicationsFile PublicationsFile { get; }

        /// <summary>
        ///     Get extended latest calendar hash chain.
        /// </summary>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain GetExtendedLatestCalendarHashChain();

        /// <summary>
        ///     Get extended calendar hash chain from given publication time.
        /// </summary>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain GetExtendedCalendarHashChain(ulong? publicationTime);
    }
}