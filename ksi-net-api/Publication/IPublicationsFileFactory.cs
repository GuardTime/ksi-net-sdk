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

using System.IO;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file factory interface.
    /// </summary>
    public interface IPublicationsFileFactory
    {
        /// <summary>
        ///     Create and verify publications file instance from stream and with given buffer size.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <param name="bufferSize">buffer size</param>
        /// <returns>publications file</returns>
        IPublicationsFile Create(Stream stream, int bufferSize);

        /// <summary>
        ///     Create and verify publications file instance from stream.
        /// </summary>
        /// <param name="stream">publications file stream</param>
        /// <returns>publications file</returns>
        IPublicationsFile Create(Stream stream);

        /// <summary>
        ///     Create and verify publications file from bytes.
        /// </summary>
        /// <param name="bytes">publications file bytes</param>
        /// <returns>publications file</returns>
        IPublicationsFile Create(byte[] bytes);
    }
}