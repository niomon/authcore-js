// Sample code for secretd export key flow
// authClient: an authenticated AuthCoreAuthClient

const { AuthCoreAuthClient } = require('authcore-js')

;(async function() {
// An authenticated client. For the secretd export flow, the process will have to be authenticated. This can be done with the Signin widget.
const authClient = await new AuthCoreAuthClient({
  clientId: 'management',
  apiBaseURL: 'https://authcore.dev:8001',
  callbacks: {
    unauthenticated: function () {
      alert('unauthenticated!')
    }
  },
  accessToken: 'eyJhbGciOiJFUzI1.....'
})

// If the user resets his contact recently, this API calls will fail with message last reset contact is too recent.
let res = await authClient.startSecretdExportAuthentication()

console.log(res)

// startSecretdExportAuthentication can be repeated call to obtain the current status.
// res["secretd_finish_authentication_time"] will be the timestamp required for the process to be completed,
// you can then call finishSecretdExportAuthentication as below.

let res2 = await authClient.finishSecretdExportAuthentication()
console.log(res2)


// for cancelling the export flow, you can call cancelSecretdExportAuthentication.
// let res3 = await authClient.cancelSecretdExportAuthentication()

})()
