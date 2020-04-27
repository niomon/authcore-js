import { AuthCoreWidgets } from './widgets.js'

export { AuthCoreAuthClient } from './auth/index.js'
export { AuthCoreManagementClient } from './management/index.js'
export { AuthCoreWidgets } from './widgets.js'
export { Authcore } from './v2/authcore'
export { AuthcoreManagement } from './v2/management'

// Provide AuthCoreWidgets in browser to provide simplest example for AuthCoreWidgets
if (global.window !== undefined && typeof global.window.define === 'function' && global.window.define.amd) {
  global.window.define('AuthCoreWidgets', function () {
    return AuthCoreWidgets
  })
} else if (global.window) {
  global.window.AuthCoreWidgets = AuthCoreWidgets
}
