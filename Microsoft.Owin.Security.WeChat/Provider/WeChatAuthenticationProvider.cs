using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.WeChat
{
    public class WeChatAuthenticationProvider : IWeChatAuthenticationProvider
    {
        public WeChatAuthenticationProvider()
        {
            OnAuthenticated = (c) => Task.FromResult<WeChatAuthenticatedContext>(null);
            OnReturnEndpoint = (c) => Task.FromResult<WeChatReturnEndpointContext>(null);
        }

        public Func<WeChatAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<WeChatReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Task Authenticated(WeChatAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public Task ReturnEndpoint(WeChatReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
