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
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Guardtime.KSI.Crypto.Microsoft.Crypto
{
    /// <summary>
    /// Certificate subject rdn selector.
    /// </summary>
    public class CertificateSubjectRdnSelector : ICertificateSubjectRdnSelector
    {
        //private static Dictionary<string, string[]> _oidMappings = new Dictionary<string, string[]>()
        //{
        //    { "2.5.4.3", new string[] { "CommonName", "CN" } },
        //    { "2.5.4.6", new string[] { "Country", "C" } },
        //    { "2.5.4.5", new string[] { "DeviceSerialNumber" } },
        //    { "0.9.2342.19200300.100.1.25", new string[] { "DomainComponent", "DC" } },
        //    { "1.2.840.113549.1.9.1", new string[] { "EMail", "E" } },
        //    { "2.5.4.42", new string[] { "GivenName", "G" } },
        //    { "2.5.4.43", new string[] { "Initials", "I" } },
        //    { "2.5.4.7", new string[] { "Locality", "L" } },
        //    { "2.5.4.10", new string[] { "Organization", "Org", "O" } },
        //    { "2.5.4.11", new string[] { "OrgUnit", "OrganizationUnit", "OrganizationalUnit", "OU" } },
        //    { "2.5.4.8", new string[] { "State", "ST", "S" } },
        //    { "2.5.4.9", new string[] { "StreetAddress", "Street" } },
        //    { "2.5.4.4", new string[] { "SurName", "SN" } },
        //    { "2.5.4.12", new string[] { "Title", "T" } },
        //    { "1.2.840.113549.1.9.8", new string[] { "UnstructuredAddress" } },
        //    { "1.2.840.113549.1.9.2", new string[] { "UnstructuredName" } }
        //};

        readonly List<string> _rdnList;

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

            _rdnList = new List<string>();
            foreach (CertificateSubjectRdn rdn in rdnList)
            {
                try
                {
                    X500DistinguishedName dname = new X500DistinguishedName(rdn.Oid + "=\"" + rdn.Value + "\"");
                    _rdnList.Add(dname.Format(false));
                }
                catch (Exception ex)
                {
                    throw new ArgumentException(string.Format("Rdn contains invalid Oid or Value. Oid: {0} Value: {1}", rdn.Oid, rdn.Value), ex);
                }
            }
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
            try
            {
                X500DistinguishedName dname = new X500DistinguishedName(subjectDn);
                _rdnList = GetRdnList(dname);
            }
            catch (Exception ex)
            {
                throw new ArgumentException(nameof(subjectDn) + " is invalid.", ex);
            }
        }

        /// <summary>
        /// Checks if certificate contains rdn selectors
        /// </summary>
        /// <param name="certificate">certificate to check</param>
        /// <returns></returns>
        public bool IsMatch(object certificate)
        {
            return Match(certificate as X509Certificate2);
        }

        /// <summary>
        /// Checks if certificate contains rdn selectors
        /// </summary>
        /// <param name="certificate">certificate to check</param>
        /// <returns></returns>
        public bool Match(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                return false;
            }

            List<string> certRdnList = GetRdnList(certificate.SubjectName);

            foreach (string rdn in _rdnList)
            {
                if (!certRdnList.Contains(rdn))
                {
                    return false;
                }
            }

            return true;
        }

        private static List<string> GetRdnList(X500DistinguishedName dname)
        {
            return new List<string>(dname.Format(true).Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries));
        }
    }
}