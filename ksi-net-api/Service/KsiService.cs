using System;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using System.Threading;
using System.IO;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Service
{
    // TODO: Implement timeout
    /// <summary>
    /// KSI service.
    /// </summary>
    public class KsiService : IKsiService
    {
        private readonly IKsiServiceProtocol _serviceProtocol;
        private readonly IKsiServiceSettings _serviceSettings;

        /// <summary>
        /// Create KSI service with service protocol and service settings.
        /// </summary>
        /// <param name="serviceProtocol">service protocol</param>
        /// <param name="serviceSettings">service settings</param>
        public KsiService(IKsiServiceProtocol serviceProtocol, IKsiServiceSettings serviceSettings)
        {
            if (serviceProtocol == null)
            {
                throw new ArgumentNullException("serviceProtocol");
            }

            if (serviceSettings == null)
            {
                throw new ArgumentNullException("serviceSettings");
            }

            _serviceProtocol = serviceProtocol;
            _serviceSettings = serviceSettings;
        }


        /// <summary>
        /// Sync create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <returns>KSI signature</returns>
        public KsiSignature CreateSignature(DataHash hash)
        {
            return EndCreateSignature(BeginCreateSignature(hash, null, null));
        }

        /// <summary>
        /// Async begin create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginCreateSignature(DataHash hash, AsyncCallback callback, object asyncState)
        {
            AggregationPdu pdu = new AggregationPdu(new KsiPduHeader(_serviceSettings.LoginId), new AggregationRequestPayload(hash));
            pdu.SetMac(_serviceSettings.LoginKey);
            IAsyncResult serviceProtocolAsyncResult = _serviceProtocol.BeginCreateSignature(pdu.Encode(), callback, asyncState);
            return new CreateSignatureKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// Async end create signature.
        /// </summary>
        /// <param name="asyncResult">async result status</param>
        /// <returns>KSI signature</returns>
        public KsiSignature EndCreateSignature(IAsyncResult asyncResult)
        {
            KsiServiceAsyncResult serviceAsyncResult = asyncResult as CreateSignatureKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                // TODO: Better name
                throw new InvalidCastException("asyncResult");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _serviceProtocol.EndCreateSignature(serviceAsyncResult.ServiceProtocolAsyncResult);
            using (MemoryStream memoryStream = new MemoryStream(data))
            using (TlvReader reader = new TlvReader(memoryStream))
            {
                // TODO: Check if it parses
                AggregationPdu tag = new AggregationPdu(reader.ReadTag());
                return new KsiSignature(tag.Payload);
            }
        }

        /// <summary>
        /// Sync extend signature to latest publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        public KsiSignature ExtendSignature(KsiSignature signature)
        {
            return EndExtendSignature(BeginExtendSignature(signature, null, null));
        }

        /// <summary>
        /// Sync extend signature to given publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication record</param>
        /// <returns>extended KSI signature</returns>
        public KsiSignature ExtendSignature(KsiSignature signature, PublicationRecord publicationRecord)
        {
            return EndExtendSignature(BeginExtendSignature(signature, publicationRecord, null, null));
        }

        /// <summary>
        /// Async begin extend signature to latest publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtendSignature(KsiSignature signature, AsyncCallback callback, object asyncState)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChain = signature.GetAggregationHashChains();
            ExtendPdu pdu = new ExtendPdu(new KsiPduHeader(_serviceSettings.LoginId), new ExtendRequestPayload(aggregationHashChain[aggregationHashChain.Count - 1].AggregationTime));
            pdu.SetMac(_serviceSettings.LoginKey);
            IAsyncResult serviceProtocolAsyncResult = _serviceProtocol.BeginExtendSignature(pdu.Encode(), callback, asyncState);
            return new ExtendSignatureKsiServiceAsyncResult(serviceProtocolAsyncResult, signature, asyncState);
        }

        /// <summary>
        /// Async begin extend signature to given publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication record</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtendSignature(KsiSignature signature, PublicationRecord publicationRecord, AsyncCallback callback, object asyncState)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }
            ReadOnlyCollection<AggregationHashChain> aggregationHashChain = signature.GetAggregationHashChains();
            // TODO: Set publication to payload
            ExtendPdu pdu = new ExtendPdu(new KsiPduHeader(_serviceSettings.LoginId), new ExtendRequestPayload(aggregationHashChain[aggregationHashChain.Count - 1].AggregationTime));
            pdu.SetMac(_serviceSettings.LoginKey);
            IAsyncResult serviceProtocolAsyncResult = _serviceProtocol.BeginExtendSignature(pdu.Encode(), callback, asyncState);
            return new ExtendSignatureKsiServiceAsyncResult(serviceProtocolAsyncResult, signature, asyncState);
        }

        /// <summary>
        /// Async end extend signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended KSI signature</returns>
        public KsiSignature EndExtendSignature(IAsyncResult asyncResult)
        {
            ExtendSignatureKsiServiceAsyncResult serviceAsyncResult = asyncResult as ExtendSignatureKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                // TODO: Better name
                throw new InvalidCastException("asyncResult");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _serviceProtocol.EndExtendSignature(serviceAsyncResult.ServiceProtocolAsyncResult);

            using (MemoryStream memoryStream = new MemoryStream(data))
            using (TlvReader reader = new TlvReader(memoryStream))
            {
                ExtendPdu tag = new ExtendPdu(reader.ReadTag());

                if (tag.Payload.Type != ExtendResponsePayload.TagType) return null;

                ExtendResponsePayload payload = tag.Payload as ExtendResponsePayload;
                if (payload == null)
                {
                    // TODO: Throw correct exception
                    throw new KsiException("Invalid response payload");
                }

                return serviceAsyncResult.Signature.Extend(payload.CalendarHashChain);
            }
        }

        /// <summary>
        /// Sync get publications file.
        /// </summary>
        /// <returns>Publications file</returns>
        public PublicationsFile GetPublicationsFile()
        {
            return EndGetPublicationsFile(BeginGetPublicationsFile(null, null));
        }

        /// <summary>
        /// Async begin get publications file.
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            IAsyncResult serviceProtocolAsyncResult = _serviceProtocol.BeginGetPublicationsFile(callback, asyncState);
            return new PublicationKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// Async end get publications file.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        public PublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            KsiServiceAsyncResult serviceAsyncResult = asyncResult as PublicationKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                // TODO: Better name
                throw new InvalidCastException("asyncResult");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _serviceProtocol.EndGetPublicationsFile(serviceAsyncResult.ServiceProtocolAsyncResult);

            return PublicationsFile.GetInstance(data);
        }

        /// <summary>
        /// Create signature KSI service async result.
        /// </summary>
        private class CreateSignatureKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public CreateSignatureKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState) : base(serviceProtocolAsyncResult, asyncState)
            {

            }
        }

        /// <summary>
        /// Extend signature KSI service async result.
        /// </summary>
        private class ExtendSignatureKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            private readonly KsiSignature _signature;

            public KsiSignature Signature
            {
                get
                {
                    return _signature;
                }
            }

            public ExtendSignatureKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, KsiSignature signature, object asyncState) : base(serviceProtocolAsyncResult, asyncState)
            {
                if (signature == null)
                {
                    throw new ArgumentNullException("signature");
                }

                _signature = signature;
            }
        }

        /// <summary>
        /// Publications file KSI service async result.
        /// </summary>
        private class PublicationKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public PublicationKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState) : base(serviceProtocolAsyncResult, asyncState)
            {

            }
        }

        /// <summary>
        /// KSI service async result.
        /// </summary>
        private abstract class KsiServiceAsyncResult : IAsyncResult
        {
            private readonly object _asyncState;
            private readonly IAsyncResult _serviceProtocolAsyncResult;

            public object AsyncState
            {
                get
                {
                    return _asyncState;
                }
            }

            public WaitHandle AsyncWaitHandle
            {
                get
                {
                    return _serviceProtocolAsyncResult.AsyncWaitHandle;
                }
            }

            public bool CompletedSynchronously
            {
                get
                {
                    return _serviceProtocolAsyncResult.CompletedSynchronously;
                }
            }

            public bool IsCompleted
            {
                get
                {
                    return _serviceProtocolAsyncResult.IsCompleted;
                }
            }

            public IAsyncResult ServiceProtocolAsyncResult
            {
                get
                {
                    return _serviceProtocolAsyncResult;
                }
            }

            protected KsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
            {
                if (serviceProtocolAsyncResult == null)
                {
                    throw new ArgumentNullException("serviceProtocolAsyncResult");
                }

                _serviceProtocolAsyncResult = serviceProtocolAsyncResult;
                _asyncState = asyncState;
            }
        }

        
    }
}
