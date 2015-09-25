using System;
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
        /// <summary>
        ///     Create publications file instance from stream and with given buffer size.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <param name="bufferSize">buffer size</param>
        /// <returns>publications file</returns>
        /// <exception cref="ArgumentNullException">thrown when stream is null</exception>
        public IPublicationsFile Create(Stream stream, int bufferSize)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            byte[] data = new byte[PublicationsFile.FileBeginningMagicBytes.Length];
            int bytesRead = stream.Read(data, 0, data.Length);

            if (bytesRead != PublicationsFile.FileBeginningMagicBytes.Length || !Util.IsArrayEqual(data, PublicationsFile.FileBeginningMagicBytes))
            {
                throw new PublicationsFileStructureException("Invalid publications file: incorrect file header");
            }

            using (MemoryStream memoryStream = new MemoryStream())
            {
                byte[] buffer = new byte[bufferSize];
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memoryStream.Write(buffer, 0, bytesRead);
                }

                PublicationsFile publicationsFile = new PublicationsFile(new RawTag(0x0, false, false, memoryStream.ToArray()));
                Verify(publicationsFile);
                return publicationsFile;
            }
        }

        /// <summary>
        ///     Create publications file from stream.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <returns>publications file</returns>
        /// <exception cref="ArgumentNullException">thrown when stream is null</exception>
        public IPublicationsFile Create(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            return Create(stream, 8092);
        }

        /// <summary>
        ///     Create publications file from bytes.
        /// </summary>
        /// <param name="bytes">publications file bytes</param>
        /// <returns>publications file</returns>
        /// <exception cref="ArgumentNullException">thrown when bytes is null</exception>
        public IPublicationsFile Create(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            using (MemoryStream stream = new MemoryStream(bytes))
            {
                return Create(stream);
            }
        }

        private static void Verify(PublicationsFile publicationsFile)
        {
            PkiTrustStoreProvider pkiTrustStoreProvider = new PkiTrustStoreProvider();
            pkiTrustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureBytes());
        }
    }
}