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
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// Certificate subject rdn selector.
    /// </summary>
    public class CertificateSubjectRdnSelector : ICertificateSubjectRdnSelector
    {
        private readonly X509Name _subjectDn;

        /// <summary>
        /// Create certificate subject rdn selector instance.
        /// </summary>
        /// <param name="rdnList">Certificate subject rdn list. Special chars must be escaped in rdn value.</param>
        public CertificateSubjectRdnSelector(IList<CertificateSubjectRdn> rdnList)
        {
            if (rdnList == null)
            {
                throw new ArgumentNullException(nameof(rdnList));
            }

            if (rdnList.Count == 0)
            {
                throw new ArgumentException("List cannot be empty.", nameof(rdnList));
            }

            List<DerObjectIdentifier> oidList = new List<DerObjectIdentifier>();
            List<string> valueList = new List<string>();

            foreach (CertificateSubjectRdn rdn in rdnList)
            {
                oidList.Add(new DerObjectIdentifier(rdn.Oid));
                valueList.Add(rdn.Value);
            }

            _subjectDn = new X509Name(oidList, valueList);
        }

        /// <summary>
        /// Create certificate subject rdn selector instance.
        /// </summary>
        /// <param name="subjectDn">Certificate subject DN.</param>
        public CertificateSubjectRdnSelector(string subjectDn)
        {
            if (string.IsNullOrEmpty(subjectDn))
            {
                throw new ArgumentException("Value cannot be empty", nameof(subjectDn));
            }

            _subjectDn = new X509Name(subjectDn);
        }

        /// <summary>
        /// Checks if certificate contains rdn selectors
        /// </summary>
        /// <param name="certificate">certificate to check</param>
        /// <returns></returns>
        public bool IsMatch(object certificate)
        {
            return Match(certificate as X509Certificate);
        }

        /// <summary>
        /// Checks if certificate contains rdn selectors
        /// </summary>
        /// <param name="certificate">certificate to check</param>
        /// <returns></returns>
        public bool Match(X509Certificate certificate)
        {
            if (certificate == null)
            {
                return false;
            }

            IList subjectDnOidList = _subjectDn.GetOidList();
            IList valueList = _subjectDn.GetValueList();

            for (int i = 0; i < subjectDnOidList.Count; i++)
            {
                if (!Contains(valueList[i], certificate.SubjectDN.GetValueList((DerObjectIdentifier)subjectDnOidList[i])))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool Contains(object searchValue, IList certificateValueList)
        {
            if (certificateValueList == null)
            {
                return false;
            }

            if (searchValue == null)
            {
                return true;
            }

            foreach (object value in certificateValueList)
            {
                if (value.Equals(searchValue))
                {
                    return true;
                }
            }

            return false;
        }
    }
}