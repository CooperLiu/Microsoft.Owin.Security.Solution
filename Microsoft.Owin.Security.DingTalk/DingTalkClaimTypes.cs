namespace Microsoft.Owin.Security.DingTalk
{
    public class DingTalkClaimTypes
    {
        public const string OpenId = "urn:ding:openid";
        public const string UnionId = "urn:ding:unionid";
        public const string AccessToken = "urn:ding:accesstoken";
        public const string PersistentCode = "urn:ding:refreshtoken";
        public const string AccessTokenExpiresUtc = "urn:ding:accesstokenexpiresutc";
    }
}