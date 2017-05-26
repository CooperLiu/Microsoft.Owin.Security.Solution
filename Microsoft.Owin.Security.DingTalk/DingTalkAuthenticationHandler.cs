using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.DingTalk
{
    internal class DingTalkAuthenticationHandler : AuthenticationHandler<DingTalkAuthenticationOptions>
    {
        private const string OAuth2AuthorizationEndpoint = "https://oapi.dingtalk.com/connect/oauth2/sns_authorize";
        private const string QrConnetAuthorizationEndpoint = "https://oapi.dingtalk.com/connect/qrconnect";
        private const string TokenEndpoint = "https://oapi.dingtalk.com/sns/gettoken";
        private const string PersistentEndpoint = "https://oapi.dingtalk.com/sns/get_persistent_code";
        private const string SnsTokenEndpoint = "https://oapi.dingtalk.com/sns/get_sns_token";
        private const string UserInfoEndpoint = "https://oapi.dingtalk.com/sns/getuserinfo";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;


        public DingTalkAuthenticationHandler(HttpClient httpClient, ILogger logger)
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

            if (!string.IsNullOrEmpty(Options.ReturnEndpointPath))
            {
                if (Request.Path.StartsWithSegments(new PathString(Options.ReturnEndpointPath))|| Options.ReturnEndpointPath == Request.Path.Value)
                {
                    var model = await AuthenticateAsync();
                    if (model == null)
                    {
                        _logger.WriteWarning("Invalid return state, unable to redirect.");
                        Response.StatusCode = 500;
                        return true;
                    }

                    var context = new DingTalkReturnEndpointContext(Context, model);
                    context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                    context.RedirectUri = model.Properties.RedirectUri;
                    model.Properties.RedirectUri = null;

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
            }

            return false;
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

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                if (string.IsNullOrEmpty(code))
                {
                    // Null if the remote server returns an error.
                    return new AuthenticationTicket(null, properties);
                }

                var appId = Options.AppId;
                var appSecrect = Options.AppSecret;

                //https://oapi.dingtalk.com/sns/gettoken?appid=APPID&appsecret=APPSECRET

                #region 获取Access Token

                var accessTokenEndpoint = $"{TokenEndpoint}?appid={appId}&appsecret={appSecrect}";

                var accessTokenResponse = await _httpClient.GetAsync(accessTokenEndpoint);
                accessTokenResponse.EnsureSuccessStatusCode();

                var accessTokenResponseStr = await accessTokenResponse.Content.ReadAsStringAsync();

                JObject accessTokenJson = JObject.Parse(accessTokenResponseStr);

                string accessToken = accessTokenJson.Value<string>("access_token");

                #endregion

                //https://oapi.dingtalk.com/sns/get_persistent_code?access_token=ACCESS_TOKEN

                #region 获取PersistentCode

                string openid = null;
                string unionid = null;
                string persistentcode = null;

                StringContent requestContent = new StringContent("{\"tmp_auth_code\": \"" + code + "\"}", Encoding.UTF8, "application/json");

                using (var message = new HttpRequestMessage(HttpMethod.Post, $"{PersistentEndpoint}?access_token={accessToken}"))
                {
                    message.Content = requestContent;

                    var res = await _httpClient.SendAsync(message, Request.CallCancelled);
                    res.EnsureSuccessStatusCode();

                    var persistentCodeStr = await res.Content.ReadAsStringAsync();

                    var persistentCodeJson = JObject.Parse(persistentCodeStr);

                    openid = persistentCodeJson.Value<string>("openid");
                    unionid = persistentCodeJson.Value<string>("unionid");
                    persistentcode = persistentCodeJson.Value<string>("persistent_code");
                }

                #endregion

                //https://oapi.dingtalk.com/sns/get_sns_token?access_token=ACCESS_TOKEN

                #region 获取用户授权的SNS_TOKEN

                string snsToken = null;
                int snsTokenExpires = 0;

                var snsRequestContent = new StringContent("{\"openid\": \"" + openid + "\",\"persistent_code\": \"" + persistentcode + "\"}", Encoding.UTF8, "application/json");

                using (var message = new HttpRequestMessage(HttpMethod.Post, $"{SnsTokenEndpoint}?access_token={accessToken}"))
                {
                    message.Content = snsRequestContent;
                    var res = await _httpClient.SendAsync(message, Request.CallCancelled);
                    res.EnsureSuccessStatusCode();

                    var snsTokenStr = await res.Content.ReadAsStringAsync();

                    var snsTokenJson = JObject.Parse(snsTokenStr);

                    snsToken = snsTokenJson.Value<string>("sns_token");
                    snsTokenExpires = snsTokenJson.Value<int>("expires_in");
                }

                #endregion

                //https://oapi.dingtalk.com/sns/getuserinfo?sns_token=SNS_TOKEN

                #region 获取用户授权的个人信息

                string userInfoUri = UserInfoEndpoint + "?sns_token=" + Uri.EscapeDataString(snsToken);
                HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(userInfoUri, Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                string userInfoString = await userInfoResponse.Content.ReadAsStringAsync();
                JObject userInfo = JObject.Parse(userInfoString);

                #endregion

                var context = new DingTalkAuthenticatedContext(Context, userInfo, accessToken, persistentcode, snsTokenExpires);
                context.Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                // Caution: 当公众帐号绑定到开放平台时，NameIdentifier == UnionId, 否则 NameIdentifier == OpenId
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.Nick))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Nick, ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.OpenId))
                {
                    context.Identity.AddClaim(new Claim(DingTalkClaimTypes.OpenId, context.OpenId, ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UnionId))
                {
                    context.Identity.AddClaim(new Claim(DingTalkClaimTypes.UnionId, context.UnionId, ClaimValueTypes.String, Options.AuthenticationType));
                }
                context.Identity.AddClaim(new Claim(DingTalkClaimTypes.AccessToken, context.AccessToken, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.PersistentCode))
                {
                    context.Identity.AddClaim(new Claim(DingTalkClaimTypes.PersistentCode, context.PersistentCode, ClaimValueTypes.String, Options.AuthenticationType));
                }
                context.Identity.AddClaim(new Claim(DingTalkClaimTypes.AccessTokenExpiresUtc, DateTimeOffset.UtcNow.Add(context.SnsTokenExpiresIn).ToString(), ClaimValueTypes.DateTime, Options.AuthenticationType));


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

                var appId = Options.AppId;
                var appSecrect = Options.AppSecret;


                var redirectUri = $"{baseUri}{Options.ReturnEndpointPath}";

                properties.RedirectUri = string.IsNullOrEmpty(properties.RedirectUri) ? currentUri : properties.RedirectUri;// + $"?returnUrl={Options.ReturnEndpointPath}";

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                var authUri = Options.AuthenticateType == DingTalkAuthenticateType.OAuth2
                    ? OAuth2AuthorizationEndpoint
                    : QrConnetAuthorizationEndpoint;

                string authorizationEndpoint =
                    authUri +
                        "?appid=" + Uri.EscapeDataString(appId) +
                        "&response_type=code" +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

    }
}
