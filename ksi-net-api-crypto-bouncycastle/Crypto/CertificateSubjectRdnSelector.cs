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
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Guardtime.KSI.Crypto.BouncyCastle.Crypto
{
    /// <summary>
    /// Certificate subject RDN selector. Used for verifying that certificate subject contains given RDN.
    /// </summary>
    public class CertificateSubjectRdnSelector : ICertificateSubjectRdnSelector
    {
        private readonly X509Name _subjectDn;

        /// <summary>
        /// Create certificate subject RDN selector instance.
        /// </summary>
        /// <param name="rdnList">List of expected RDNs. Special chars must be escaped in RDN value.</param>
        public CertificateSubjectRdnSelector(IList<CertificateSubjectRdn> rdnList)
        {
            if (rdnList == null)
            {
                throw new ArgumentNullException(nameof(rdnList));
            }

            if (rdnList.Count == 0)
            {
                throw new ArgumentException("RDN list cannot be empty.", nameof(rdnList));
            }

            List<DerObjectIdentifier> oidList = new List<DerObjectIdentifier>();
            List<string> valueList = new List<string>();

            foreach (CertificateSubjectRdn rdn in rdnList)
            {
                try
                {
                    // try to get by name first (expect Oid contain name). DefaultLookup contains "name"=> DerObjectIdentifier pairs)
                    oidList.Add(X509Name.DefaultLookup[rdn.Oid.ToLower()] as DerObjectIdentifier ?? new DerObjectIdentifier(rdn.Oid));
                    valueList.Add(rdn.Value);
                }
                catch (Exception ex)
                {
                    throw new ArgumentException(string.Format("Rdn contains invalid Oid or Value. Oid: {0} Value: {1}", rdn.Oid, rdn.Value), ex);
                }
            }

            _subjectDn = new X509Name(oidList, valueList);
        }

        /// <summary>
        /// Create certificate subject RDN selector instance.
        /// </summary>
        /// <param name="rdn">Expected RDN. Special chars must be escaped in RDN value.</param>
        public CertificateSubjectRdnSelector(params string[] rdn)
        {
            if (rdn.Length == 0)
            {
                throw new ArgumentException("At least one RDN must be given.");
            }

            string s = "";
            foreach (string d in rdn)
            {
                if (string.IsNullOrEmpty(d))
                {
                    throw new ArgumentException("RDN cannot be empty.");
                }

                if (!string.IsNullOrEmpty(s))
                {
                    s += ",";
                }
                s += d;
            }
            _subjectDn = new X509Name(s);
        }

        /// <summary>
        /// Checks if certificate subject contains specified RDNs.
        /// </summary>
        /// <param name="certificate">certificate to check</param>
        /// <returns></returns>
        public bool IsMatch(object certificate)
        {
            return Match(certificate as X509Certificate);
        }

        /// <summary>
        /// Checks if certificate subject contains specified RDNs.
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