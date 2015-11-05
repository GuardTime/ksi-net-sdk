using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file factory for creating publications file instance.
    /// </summary>
    public partial class PublicationsFileFactory
    {
        private readonly IPkiTrustProvider _pkiTrustProvider;

        /// <summary>
        ///     Create new publications file factory with PKI trust provider.
        /// </summary>
        /// <param name="pkiTrustProvider">pki trust provider</param>
        /// <exception cref="KsiException">thrown when PKI trust provider is null</exception>
        public PublicationsFileFactory(IPkiTrustProvider pkiTrustProvider)
        {
            if (pkiTrustProvider == null)
            {
                throw new KsiException("Invalid PKI trust provider: null.");
            }

            _pkiTrustProvider = pkiTrustProvider;
        }

        /// <summary>
        ///     Create and verify publications file instance from stream and with given buffer size.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <param name="bufferSize">buffer size</param>
        /// <returns>publications file</returns>
        /// <exception cref="KsiException">thrown when stream is null</exception>
        /// <exception cref="PublicationsFileException">thrown when publications file data is invalid</exception>
        public IPublicationsFile Create(Stream stream, int bufferSize)
        {
            if (stream == null)
            {
                throw new KsiException("Invalid input stream: null.");
            }

            byte[] data = new byte[PublicationsFile.FileBeginningMagicBytes.Length];
            int bytesRead = stream.Read(data, 0, data.Length);

            if (bytesRead != PublicationsFile.FileBeginningMagicBytes.Length ||
                !Util.IsArrayEqual(data, PublicationsFile.FileBeginningMagicBytes))
            {
                throw new PublicationsFileException("Publications file header is incorrect.");
            }

            using (MemoryStream memoryStream = new MemoryStream())
            {
                byte[] buffer = new byte[bufferSize];
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memoryStream.Write(buffer, 0, bytesRead);
                }

                PublicationsFile publicationsFile =
                    new PublicationsFile(new RawTag(0x0, false, false, memoryStream.ToArray()));

                try
                {
                    Verify(publicationsFile);
                }
                catch (PkiVerificationException e)
                {
                    throw new PublicationsFileException("Publications file verification failed.", e);
                }

                return publicationsFile;
            }
        }

        /// <summary>
        ///     Create and verify publications file from stream.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <returns>publications file</returns>
        /// <exception cref="KsiException">thrown when stream is null</exception>
        /// <exception cref="PublicationsFileException">thrown when publications file data is invalid</exception>
        public IPublicationsFile Create(Stream stream)
        {
            if (stream == null)
            {
                throw new KsiException("Invalid input stream: null.");
            }

            return Create(stream, 8092);
        }

        /// <summary>
        ///     Create and verify publications file from bytes.
        /// </summary>
        /// <param name="bytes">publications file bytes</param>
        /// <returns>publications file</returns>
        /// <exception cref="KsiException">thrown when bytes is null</exception>
        /// <exception cref="PublicationsFileException">thrown when publications file data is invalid</exception>
        public IPublicationsFile Create(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new KsiException("Invalid input data: null.");
            }

            using (MemoryStream stream = new MemoryStream(bytes))
            {
                return Create(stream);
            }
        }

        private void Verify(PublicationsFile publicationsFile)
        {
            _pkiTrustProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureBytes());
        }
    }
}