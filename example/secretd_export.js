
// Sample code for secretd export key flow
// authClient: an authenticated AuthCoreAuthClient

// If the user resets his password via forget password flow (not via user setting as that requires old password) recently,
// this API calls will fail with message last reset password is too recent.
let res = await authClient.startSecretdExportAuthentication()
// If the user requires password to authenticate, res.challenges with be ["PASSWORD"]
// else res.challenges will be empty, i.e. the user DO NOT have password already set to do the authentication.
if (res.challenges.includes("PASSWORD")) {
  // require user to key in his password
  // here password is the user's password
  let res2 = await authClient.authenticateSecretdWithPassword(password)
  // if this request fails, the user have input wrong password. This request is rate limited as in login process, 
  // if it fails for a number of times, the users account will be locked.
  secretd_access_token = res2.secretd_access_token
} else {
  // For user have no password set, this API will directly return the secretd access token.
  let res2 = await authClient.authenticateSecretdWithNoPassword()
  secretd_access_token = res2.secretd_access_token
}
