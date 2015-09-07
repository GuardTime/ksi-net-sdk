using System;
using System.IO;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    /// Publications file factory for creating publications file instance.
    /// </summary>
    public class PublicationsFileFactory
    {
        /// <summary>
        /// Create publications file instance from stream and with given buffer size.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <param name="bufferSize">buffer size</param>
        /// <returns>publications file</returns>
        public PublicationsFile Create(Stream stream, int bufferSize)
        {
            PublicationsFile publicationsFile = PublicationsFile.GetInstance(stream, bufferSize);
            Verify(publicationsFile);
            return publicationsFile;
        }

        /// <summary>
        /// Create publications file from stream.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <returns>publications file</returns>
        public PublicationsFile Create(Stream stream)
        {
            PublicationsFile publicationsFile = PublicationsFile.GetInstance(stream);
            Verify(publicationsFile);
            return publicationsFile;
        }

        /// <summary>
        /// Create publications file from bytes.
        /// </summary>
        /// <param name="bytes">publications file bytes</param>
        /// <returns>publications file</returns>
        public PublicationsFile Create(byte[] bytes)
        {
            PublicationsFile publicationsFile = PublicationsFile.GetInstance(bytes);
            Verify(publicationsFile);
            return publicationsFile;
        }

        private void Verify(PublicationsFile publicationsFile)
        {
            PkiTrustStoreProvider pkiTrustStoreProvider = new PkiTrustStoreProvider();
            pkiTrustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureBytes());
        }
    }
}