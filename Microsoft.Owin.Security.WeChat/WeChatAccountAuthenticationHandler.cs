using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.WeChat
{
    internal class WeChatAccountAuthenticationHandler : AuthenticationHandler<WeChatAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string AuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect";
        private const string OAuth2AuthorizationEndpoint = "https://open.weixin.qq.com/connect/oauth2/authorize";
        private const string TokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";
        private const string UserInfoEndpoint = "https://api.weixin.qq.com/sns/userinfo";
        private const string OpenIDEndpoint = "https://api.weixin.qq.com/sns/oauth2";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        private bool IsWeChatBrowser
        {
            get
            {
                var userAgent = Context.Request.Headers.Get("User-Agent");
                return userAgent != null && (Options.IsSupportWechatBrower && userAgent.Contains("MicroMessenger"));
            }
        }

        public WeChatAccountAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.ReturnEndpointPath != null &&
                String.Equals(Options.ReturnEndpointPath, Request.Path.Value, StringComparison.OrdinalIgnoreCase))
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        private async Task<bool> InvokeReturnPathAsync()
        {
            _logger.WriteVerbose("InvokeReturnPath");

            bool isWeChatBrowser = IsWeChatBrowser;

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                System.Diagnostics.Debug.WriteLine("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new WeChatReturnEndpointContext(Context, ticket);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            // context.RedirectUri = model.Properties.RedirectUri;
            context.RedirectUri = isWeChatBrowser ? Request.Query["ReturnUrl"] : context.RedirectUri = ticket.Properties.RedirectUri;   // Hate WeChat

            ticket.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);
            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            _logger.WriteVerbose("AuthenticateCore");


            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;

                IList<string> values = query.GetValues("error");
                if (values != null && values.Count >= 1)
                    _logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);

                values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                bool isWeChatBrowser = IsWeChatBrowser;


                // OAuth2 10.12 CSRF
                if (!isWeChatBrowser && !ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                if (string.IsNullOrEmpty(code))
                {
                    // Null if the remote server returns an error.
                    return new AuthenticationTicket(null, properties);
                }

                var appId = isWeChatBrowser ? Options.WechatAppId : Options.AppId;
                var appSecrect = isWeChatBrowser ? Options.WechatAppSecret : Options.AppSecret;

                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("appid", appId), //扫码登陆使用网站应用，网页授权使用公众号应用
                    new KeyValuePair<string, string>("secret", appSecrect),//扫码登陆使用网站应用，网页授权使用公众号应用
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };

                FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);

                HttpResponseMessage response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                string oauthTokenResponse = await response.Content.ReadAsStringAsync();
                JObject json = JObject.Parse(oauthTokenResponse);

                string accessToken = json.Value<string>("access_token");
                string refreshToken = json.Value<string>("refresh_token");
                int expires = json.Value<int>("expires_in");
                string openId = json.Value<string>("openid");


                string userInfoUri = UserInfoEndpoint +
                    "?access_token=" + Uri.EscapeDataString(accessToken) +
                    "&openid=" + Uri.EscapeDataString(openId);
                HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(userInfoUri, Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                string userInfoString = await userInfoResponse.Content.ReadAsStringAsync();
                JObject userInfo = JObject.Parse(userInfoString);

                var context = new WeChatAuthenticatedContext(Context, userInfo, accessToken, refreshToken, expires);
                context.Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                // Caution: 当公众帐号绑定到开放平台时，NameIdentifier == UnionId, 否则 NameIdentifier == OpenId
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.OpenId))
                {
                    context.Identity.AddClaim(new Claim(WeChatClaimTypes.OpenId, context.OpenId, ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UnionId))
                {
                    context.Identity.AddClaim(new Claim(WeChatClaimTypes.UnionId, context.UnionId, ClaimValueTypes.String, Options.AuthenticationType));
                }
                context.Identity.AddClaim(new Claim(WeChatClaimTypes.AccessToken, context.AccessToken, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.RefreshToken))
                {
                    context.Identity.AddClaim(new Claim(WeChatClaimTypes.RefreshToken, context.RefreshToken, ClaimValueTypes.String, Options.AuthenticationType));
                }
                context.Identity.AddClaim(new Claim(WeChatClaimTypes.AccessTokenExpiresUtc, DateTimeOffset.UtcNow.Add(context.ExpiresIn).ToString(), ClaimValueTypes.DateTime, Options.AuthenticationType));


                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }

            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            _logger.WriteVerbose("ApplyResponseChallenge");

            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                var baseUri = Request.Scheme + "://" + Request.Host + Request.PathBase;
                string currentQueryString = Request.QueryString.Value;
                string currentUri = string.IsNullOrEmpty(currentQueryString)
                    ? baseUri + Request.Path
                    : baseUri + Request.Path + "?" + currentQueryString;

                AuthenticationProperties properties = challenge.Properties;


                string redirectUri = null;
                var isWeChatBrowser = IsWeChatBrowser;

                var appId = isWeChatBrowser ? Options.WechatAppId : Options.AppId;
                var appSecrect = isWeChatBrowser ? Options.WechatAppSecret : Options.AppSecret;


                if (isWeChatBrowser)
                {
                    var callbackRedirectUri = string.IsNullOrEmpty(properties.RedirectUri) ? currentUri : properties.RedirectUri;

                    properties.RedirectUri = null;

                    redirectUri = $"{baseUri}{Options.ReturnEndpointPath}?ReturnUrl={Uri.EscapeDataString(callbackRedirectUri)}";
                }
                else
                {
                    redirectUri = $"{baseUri}{Options.ReturnEndpointPath}";

                    properties.RedirectUri = string.IsNullOrEmpty(properties.RedirectUri) ? currentUri : properties.RedirectUri;

                    // OAuth2 10.12 CSRF
                    GenerateCorrelationId(properties);
                }

                // comma separated
                string scope = isWeChatBrowser ? string.Join(",", Options.WechatScope) : string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                var authUri = isWeChatBrowser ? OAuth2AuthorizationEndpoint : AuthorizationEndpoint;

                string authorizationEndpoint =
                    authUri +
                        "?appid=" + Uri.EscapeDataString(appId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&response_type=code" +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state) +
                        "#wechat_redirect";

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

    }
}
