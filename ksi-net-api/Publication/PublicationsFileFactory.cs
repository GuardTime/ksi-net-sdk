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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file factory for creating publications file instance.
    /// </summary>
    public class PublicationsFileFactory : IPublicationsFileFactory
    {
        private readonly IPkiTrustProvider _pkiTrustProvider;
        private const int DefaultBufferSize = 8092;
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        ///     Create new publications file factory with PKI trust provider.
        /// </summary>
        /// <param name="pkiTrustProvider">pki trust provider</param>
        public PublicationsFileFactory(IPkiTrustProvider pkiTrustProvider)
        {
            if (pkiTrustProvider == null)
            {
                throw new ArgumentNullException(nameof(pkiTrustProvider));
            }

            _pkiTrustProvider = pkiTrustProvider;
        }

        /// <summary>
        ///     Create and verify publications file instance from stream and with given buffer size.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <param name="bufferSize">buffer size</param>
        /// <returns>publications file</returns>
        public IPublicationsFile Create(Stream stream, int bufferSize)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            Logger.Debug("Creating publications file.");

            byte[] data = new byte[PublicationsFile.FileBeginningMagicBytes.Length];
            int bytesRead = stream.Read(data, 0, data.Length);

            if (bytesRead != PublicationsFile.FileBeginningMagicBytes.Length || !Util.IsArrayEqual(data, PublicationsFile.FileBeginningMagicBytes))
            {
                throw new PublicationsFileException("Publications file header is incorrect. Invalid publications file magic bytes.");
            }

            using (MemoryStream memoryStream = new MemoryStream())
            {
                byte[] buffer = new byte[bufferSize];
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memoryStream.Write(buffer, 0, bytesRead);
                }

                PublicationsFile publicationsFile = new PublicationsFile(new RawTag(0x0, false, false, memoryStream.ToArray()));

                try
                {
                    Verify(publicationsFile);
                }
                catch (PkiVerificationException e)
                {
                    Logger.Warn("Publications file verification failed. {0}", e);
                    throw new PublicationsFileException("Publications file verification failed.", e);
                }

                Logger.Debug("Publications file created.");

                return publicationsFile;
            }
        }

        /// <summary>
        ///     Create and verify publications file instance from stream.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <returns>publications file</returns>
        public IPublicationsFile Create(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            return Create(stream, DefaultBufferSize);
        }

        /// <summary>
        ///     Create and verify publications file from bytes.
        /// </summary>
        /// <param name="bytes">publications file bytes</param>
        /// <returns>publications file</returns>
        public IPublicationsFile Create(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            using (MemoryStream stream = new MemoryStream(bytes))
            {
                return Create(stream);
            }
        }

        private void Verify(PublicationsFile publicationsFile)
        {
            _pkiTrustProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }
    }
}