using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Guardtime.KSI.Crypto
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

        private static List<string> GetRdnList(X500DistinguishedName dname)
        {
            return new List<string>(dname.Format(true).Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries));
        }

        public bool Match(object obj)
        {
            return Match(obj as X509Certificate2);
        }

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
    }
}