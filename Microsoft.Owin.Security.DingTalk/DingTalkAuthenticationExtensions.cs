using System;
using Microsoft.Owin.Security.DingTalk;
using Microsoft.Owin.Security;

namespace Owin
{
    public static class DingTalkAuthenticationExtensions
    {
        public static void UseWeChatAuthentication(this IAppBuilder app, DingTalkAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(DingTalkAuthenticationMiddleware), app, options);
        }

        public static void UseWeChatAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            UseWeChatAuthentication(app, new DingTalkAuthenticationOptions()
            {
                AppId = appId,
                AppSecret = appSecret,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            });
        }
    }
}
