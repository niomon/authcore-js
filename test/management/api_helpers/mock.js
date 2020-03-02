const nock = require('nock')

function mockAPI(steps) {
  nock.cleanAll()
  steps.forEach(function (step) {
    let { type, count } = step
    if (count === undefined) count = 1
    switch (type) {
      case 'SwaggerClient':
        nock('http://0.0.0.0:13337').get('/api/authapi/authcore.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../authcore.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerMgmtClient':
        nock('http://0.0.0.0:13337').get('/api/managementapi/management.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../management.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerClient404':
        nock('http://0.0.0.0:13337').get('/api/authapi/authcore.swagger.json').times(count)
          .reply(404, '404 page not found')
        break
      case 'SwaggerMgmtClient404':
        nock('http://0.0.0.0:13337').get('/api/managementapi/management.swagger.json').times(count)
          .reply(404, '404 page not found')
        break
      case 'GeneralAuthFail':
        nock('http://0.0.0.0:13337').get('/api/auth/users/current').times(count)
          .reply(
            400, { code: 3, error: 'InvalidArgument', message: 'InvalidArgument' }
          )
        break
      case 'GeneralMgmtFail':
        nock('http://0.0.0.0:13337').post('/api/management/users').times(count)
          .reply(
            403, { code: 7, error: 'unauthorized', message: 'unauthorized' }
          )
        break
      case 'CreateAccessToken':
        nock('http://0.0.0.0:13337').post('/api/auth/tokens').times(count)
          .replyWithFile(
            200, `${__dirname}/create_access_token.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers':
        nock('http://0.0.0.0:13337').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_users.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers401':
        nock('http://0.0.0.0:13337').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            401, `${__dirname}/list_users_401.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers403':
        nock('http://0.0.0.0:13337').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            403, `${__dirname}/list_users_403.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetUser':
        nock('http://0.0.0.0:13337').get('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/get_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateUser':
        nock('http://0.0.0.0:13337').put('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/update_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_Email':
        nock('http://0.0.0.0:13337').post('/api/management/users/1/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_email_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_Phone':
        nock('http://0.0.0.0:13337').post('/api/management/users/1/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_phone_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteContact':
        nock('http://0.0.0.0:13337').delete('/api/management/contacts/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListContacts':
        nock('http://0.0.0.0:13337').get('/api/management/users/1/contacts?type=email').times(count)
          .replyWithFile(
            200, `${__dirname}/list_contacts.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdatePrimaryContact':
        nock('http://0.0.0.0:13337').put('/api/management/contacts/1/primary').times(count)
          .replyWithFile(
            200, `${__dirname}/update_primary_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartVerifyContact':
        nock('http://0.0.0.0:13337').post('/api/management/contacts/verify').times(count)
          .replyWithFile(
            200, `${__dirname}/start_verify_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListAuditLogs':
        nock('http://0.0.0.0:13337').get('/api/management/audit_logs?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUserAuditLogs':
        nock('http://0.0.0.0:13337').get('/api/management/audit_logs?page_size=10&ascending=false&user_id=1').times(count)
          .replyWithFile(
            200, `${__dirname}/list_user_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRoles':
        nock('http://0.0.0.0:13337').get('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_roles.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateRole':
        nock('http://0.0.0.0:13337').post('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/create_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteRole':
        nock('http://0.0.0.0:13337').delete('/api/management/roles/5').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AssignRole':
        nock('http://0.0.0.0:13337').post('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/assign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UnassignRole':
        nock('http://0.0.0.0:13337').delete('/api/management/users/5/roles/3').times(count)
          .replyWithFile(
            200, `${__dirname}/unassign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRoleAssignments':
        nock('http://0.0.0.0:13337').get('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_role_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListPermissionAssignments':
        nock('http://0.0.0.0:13337').get('/api/management/roles/1/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_permission_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListCurrentUserPermissions':
        nock('http://0.0.0.0:13337').get('/api/management/users/current/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_current_user_permissions.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListSessions':
        nock('http://0.0.0.0:13337').get('/api/management/sessions?user_id=1&page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_sessions.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteSession':
        nock('http://0.0.0.0:13337').delete('/api/management/sessions/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_session.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetMetadata':
        nock('http://0.0.0.0:13337').get('/api/management/users/1/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/get_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateMetadata':
        nock('http://0.0.0.0:13337').put('/api/management/users/1/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/update_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateUser':
        nock('http://0.0.0.0:13337').post('/api/management/users').times(count)
          .replyWithFile(
            200, `${__dirname}/create_user_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePassword':
        nock('http://0.0.0.0:13337').post('/api/management/users/password').times(count)
          .replyWithFile(
            200, `${__dirname}/change_password_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerClientForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/authapi/authcore.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../authcore.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerMgmtClientForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/managementapi/management.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../management.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerClient404ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/authapi/authcore.swagger.json').times(count)
          .reply(404, '404 page not found')
        break
      case 'SwaggerMgmtClient404ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/managementapi/management.swagger.json').times(count)
          .reply(404, '404 page not found')
        break
      case 'ListUsersForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_users.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers401ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            401, `${__dirname}/list_users_401.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers403ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            403, `${__dirname}/list_users_403.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetUserForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/get_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateUserForHTTPS':
        nock('https://0.0.0.0:13338').put('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/update_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListContactsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/1/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/list_contacts.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListAuditLogsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/audit_logs?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUserAuditLogsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/audit_logs?page_size=10&ascending=false&user_id=1').times(count)
          .replyWithFile(
            200, `${__dirname}/list_user_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRolesForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_roles.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateRoleForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/create_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteRoleForHTTPS':
        nock('https://0.0.0.0:13338').delete('/api/management/roles/5').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AssignRoleForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/assign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UnassignRoleForHTTPS':
        nock('https://0.0.0.0:13338').delete('/api/management/users/5/roles/3').times(count)
          .replyWithFile(
            200, `${__dirname}/unassign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRoleAssignmentsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_role_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListPermissionAssignmentsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/roles/1/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_permission_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListCurrentUserPermissionsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/current/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_current_user_permissions.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateUserByAdminForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/users').times(count)
          .replyWithFile(
            200, `${__dirname}/create_user_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePasswordByAdminForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/users/password').times(count)
          .replyWithFile(
            200, `${__dirname}/change_password_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
    }
  })
}

exports.mockAPI = mockAPI
