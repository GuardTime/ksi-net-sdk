using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Guardtime.KSI.Service
{
    public class HttpAggregationRequest
    {
        public HttpAggregationRequest()
        {
            var request = WebRequest.Create("http://ksigw.test.guardtime.com:3333/gt-signingservice");
            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            var tag = new AggregationPdu();
            var data = tag.Encode();
            data = new byte[] {};
            request.ContentLength = data.Length; 
            var stream = request.GetRequestStream();
            stream.Write(data, 0, data.Length);
            stream.Close();
            Console.WriteLine(tag);
            Console.WriteLine(request.GetResponse());
        }
    }
}
