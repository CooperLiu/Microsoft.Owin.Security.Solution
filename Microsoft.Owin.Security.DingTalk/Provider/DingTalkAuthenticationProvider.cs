using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.DingTalk
{
    public class DingTalkAuthenticationProvider : IDingTalkAuthenticationProvider
    {
        public DingTalkAuthenticationProvider()
        {
            OnAuthenticated = (c) => Task.FromResult<DingTalkAuthenticatedContext>(null);
            OnReturnEndpoint = (c) => Task.FromResult<DingTalkReturnEndpointContext>(null);
        }

        public Func<DingTalkAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<DingTalkReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Task Authenticated(DingTalkAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public Task ReturnEndpoint(DingTalkReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
