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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class TestVerificationContext : IVerificationContext
    {
        public DataHash DocumentHash { get; set; }
        public IKsiSignature Signature { get; set; }
        public PublicationData UserPublication { get; set; }
        public IKsiService KsiService { get; set; }
        public bool IsExtendingAllowed { get; set; }
        public IPublicationsFile PublicationsFile { get; set; }

        public CalendarHashChain LatestCalendarHashChain;

        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return LatestCalendarHashChain;
        }

        public CalendarHashChain ExtendedCalendarHashChain;

        public CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime)
        {
            return ExtendedCalendarHashChain;
        }
    }
}