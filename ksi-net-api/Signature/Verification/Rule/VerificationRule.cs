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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using NLog;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Verification rule.
    /// </summary>
    public abstract class VerificationRule
    {
        private VerificationRule _onFailure;
        private VerificationRule _onNa;
        private VerificationRule _onSuccess;

        protected static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Get rule name.
        /// </summary>
        /// <returns></returns>
        public string GetRuleName()
        {
            return GetType().Name;
        }

        /// <summary>
        ///     Get next rule based on verification result.
        /// </summary>
        /// <param name="resultCode">verification result</param>
        /// <returns>next verification rule</returns>
        public VerificationRule NextRule(VerificationResultCode resultCode)
        {
            switch (resultCode)
            {
                case VerificationResultCode.Ok:
                    return _onSuccess;
                case VerificationResultCode.Fail:
                    return _onFailure;
                case VerificationResultCode.Na:
                    return _onNa;
                default:
                    return null;
            }
        }

        /// <summary>
        ///     Set next verification rule on success.
        /// </summary>
        /// <param name="onSuccess">next verification rule on success</param>
        /// <returns>current verification rule</returns>
        public VerificationRule OnSuccess(VerificationRule onSuccess)
        {
            _onSuccess = onSuccess;
            return this;
        }

        /// <summary>
        ///     Set next verification rule on na status.
        /// </summary>
        /// <param name="onNa">next verification rule on na status</param>
        /// <returns>current verification rule</returns>
        public VerificationRule OnNa(VerificationRule onNa)
        {
            _onNa = onNa;
            return this;
        }

        /// <summary>
        ///     Set next verification rule on failure.
        /// </summary>
        /// <param name="onFailure">next verification rule on failure</param>
        /// <returns>current verification rule</returns>
        public VerificationRule OnFailure(VerificationRule onFailure)
        {
            _onFailure = onFailure;
            return this;
        }

        /// <summary>
        ///     Verify given context with verification rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public abstract VerificationResult Verify(IVerificationContext context);

        /// <summary>
        /// Check if verification context is valid.
        /// </summary>
        /// <param name="context">verification context</param>
        public static void CheckVerificationContext(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
        }

        /// <summary>
        /// Get KSi signature from verification context
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>KSI signature</returns>
        public static IKsiSignature GetSignature(IVerificationContext context)
        {
            CheckVerificationContext(context);

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            return context.Signature;
        }

        /// <summary>
        ///     Get aggregation hash chain collection from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="canBeEmpty">indicates if aggregation has chain collection can be empty</param>
        /// <returns>aggregation hash chain collection</returns>
        public static ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains(IKsiSignature signature, bool canBeEmpty)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = signature.GetAggregationHashChains();

            if (!canBeEmpty && (aggregationHashChains == null || aggregationHashChains.Count == 0))
            {
                throw new KsiVerificationException("Aggregation hash chains are missing from KSI signature.");
            }

            return aggregationHashChains ?? new ReadOnlyCollection<AggregationHashChain>(new AggregationHashChain[] { });
        }

        /// <summary>
        /// Get publications file form verification context
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>publications file</returns>
        public static IPublicationsFile GetPublicationsFile(IVerificationContext context)
        {
            CheckVerificationContext(context);

            if (context.PublicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file in context: null.");
            }

            return context.PublicationsFile;
        }

        /// <summary>
        /// Get calendar has chain from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="allowNullValue">indicates if returning null value is allowed</param>
        /// <returns>calendar hash chain</returns>
        public static CalendarHashChain GetCalendarHashChain(IKsiSignature signature, bool allowNullValue = false)
        {
            CalendarHashChain calendarHashChain = signature.CalendarHashChain;
            if (!allowNullValue && calendarHashChain == null)
            {
                throw new KsiVerificationException("Calendar hash chain is missing from KSI signature.");
            }
            return calendarHashChain;
        }

        /// <summary>
        /// Get calendar authentication record from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>calendar authentication record</returns>
        public static CalendarAuthenticationRecord GetCalendarAuthenticationRecord(IKsiSignature signature)
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new KsiVerificationException("Calendar authentication record in missing from KSI signature.");
            }
            return calendarAuthenticationRecord;
        }

        /// <summary>
        /// Get publication record from KSI signature
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>publication record</returns>
        public static PublicationRecordInSignature GetPublicationRecord(IKsiSignature signature)
        {
            PublicationRecordInSignature publicationRecord = signature.PublicationRecord;

            if (publicationRecord == null)
            {
                throw new KsiVerificationException("Publication record is missing from KSI signature.");
            }

            return publicationRecord;
        }

        /// <summary>
        /// Get user publication from verification context
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>user publication</returns>
        public static PublicationData GetUserPublication(IVerificationContext context)
        {
            CheckVerificationContext(context);

            PublicationData userPublication = context.UserPublication;

            if (context.UserPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null.");
            }
            return userPublication;
        }

        /// <summary>
        ///  Get extended calendar hash chain from given publication time.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns></returns>
        public static CalendarHashChain GetExtendedCalendarHashChain(IVerificationContext context, ulong publicationTime)
        {
            CalendarHashChain hashChain = context.GetExtendedCalendarHashChain(publicationTime);

            if (hashChain == null)
            {
                throw new KsiVerificationException("Received invalid extended calendar hash chain from context extension function: null.");
            }

            return hashChain;
        }

        /// <summary>
        /// Get publication record from publications file that is nearest to the given time.
        /// </summary>
        /// <param name="publicationsFile">publications file</param>
        /// <param name="time">time</param>
        /// <param name="allowNullValue">indicates if returning null value is allowed</param>
        /// <returns></returns>
        public static PublicationRecordInPublicationFile GetNearestPublicationRecord(IPublicationsFile publicationsFile, ulong time, bool allowNullValue = false)
        {
            PublicationRecordInPublicationFile publicationRecord = publicationsFile.GetNearestPublicationRecord(time);

            if (!allowNullValue && publicationRecord == null)
            {
                throw new KsiVerificationException("No publication record found after given time in publications file: " + time + ".");
            }
            return publicationRecord;
        }

        /// <summary>
        /// Get first deprecated hash algorithm from calendar hash chain.
        /// </summary>
        /// <param name="calendarHashChain"></param>
        /// <returns></returns>
        public HashAlgorithm GetDeprecatedHashAlgorithm(CalendarHashChain calendarHashChain)
        {
            IEnumerator<CalendarHashChain.Link> linksEnumerator = calendarHashChain.GetLeftLinksEnumerator();
            CalendarHashChain.Link link = linksEnumerator.MoveNext() ? linksEnumerator.Current : null;

            while (link != null)
            {
                if (link.Value.Algorithm.IsDeprecated(calendarHashChain.PublicationTime))
                {
                    return link.Value.Algorithm;
                }

                link = linksEnumerator.MoveNext() ? linksEnumerator.Current : null;
            }

            return null;
        }
    }
}