/* global suite, test */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
const nock = require('nock')

const { mockAPI } = require('./api_helpers/mock.js')
const { AuthCoreManagementClient } = require('../../src/management/index.js')

chai.use(chaiAsPromised)
const { assert } = chai

suite('management/index.js', function () {
  suite('AuthCoreManagementClient', function () {
    test('should be able to list users', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUsers' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const usersObject = await authcoreClient.listUsers(10, '', false)
      assert.isArray(usersObject['users'])
      assert.equal(usersObject['next_page_token'], '2')
      assert.equal(usersObject['total_size'], 1)
      assert.isTrue(nock.isDone())
    })

    test('should be able to get a specifed user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'GetUser' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })

      const userObject = await authcoreClient.getUser('1')
      assert.equal(userObject['id'], '1')
      assert.equal(userObject['username'], 'samuel')
      assert.equal(userObject['email'], 'samuel@blocksq.com')
      assert.equal(userObject['phone'], '+85299965536')
      assert.equal(userObject['display_name'], 'Samuel')
      assert.isTrue(nock.isDone())
    })

    test('should be able to update user profiles', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'GetUser' },
        { type: 'UpdateUser' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      let user = await authcoreClient.getUser('1')
      user['display_name'] = 'Samuel_updated'

      const updatedUser = await authcoreClient.updateUserProfile('1', user)
      assert.equal(updatedUser['id'], '1')
      assert.equal(updatedUser['username'], 'samuel')
      assert.equal(updatedUser['email'], 'samuel@blocksq.com')
      assert.equal(updatedUser['phone'], '+85299965536')
      assert.equal(updatedUser['display_name'], 'Samuel_updated')
      assert.isTrue(nock.isDone())
    })

    test('should be able to lock or unlock users', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'UpdateUser', count: 3 }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      // Trial 1: Lock for 7 days
      await assert.isFulfilled(
        authcoreClient.updateUserLock('1', true, 7, 'Misbehaviour')
      )
      // Trial 2: Lock permanently
      await assert.isFulfilled(
        authcoreClient.updateUserLock('1', true, Infinity, 'Misbehaviour')
      )
      // Trial 3: Unlock
      await assert.isFulfilled(
        authcoreClient.updateUserLock('1', false, 'Banned the wrong guy')
      )
      // Trial 4: Lock for 0 days (throws without calling an API)
      await assert.isRejected(
        authcoreClient.updateUserLock('1', true, 0, 'This is a bad move...'),
        'lock in days should be positive'
      )
      assert.isTrue(nock.isDone())
    })

    test('should be able to create an email contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'CreateContact_Email' },
        { type: 'StartVerifyContact' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.createEmailContact(1, 'example@example.com')
      assert.isTrue(nock.isDone())
    })

    test('should be able to create a phone contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'CreateContact_Phone' },
        { type: 'StartVerifyContact' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.createPhoneContact(1, '+85298765432')
      assert.isTrue(nock.isDone())
    })

    test('should be able to list the contacts', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListContacts' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.listContacts(1, 'email')
      assert.isTrue(nock.isDone())
    })

    test('should be able to set primary contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'UpdatePrimaryContact' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.updatePrimaryContact(1)
      assert.isTrue(nock.isDone())
    })

    test('should be able to delete contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'DeleteContact' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.deleteContact(1)
      assert.isTrue(nock.isDone())
    })

    test('should list all audit logs', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListAuditLogs' }
      ])

      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const auditLogs = await authcoreClient.listAuditLogs(10, '', false)
      assert.isArray(auditLogs['auditLogs'])
      assert.equal(auditLogs['next_page_token'], '4')
      assert.equal(auditLogs['total_size'], 3)
      assert.isTrue(nock.isDone())
    })

    test('should list all audit logs of a certain user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUserAuditLogs' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const auditLogsObject = await authcoreClient.listUserAuditLogs(1, 10, '', false)
      assert.isArray(auditLogsObject.auditLogs)
      assert.equal(auditLogsObject.next_page_token, '4')
      assert.equal(auditLogsObject.total_size, 3)
      assert.isTrue(nock.isDone())
    })

    test('should be able to list roles', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListRoles' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const roles = await authcoreClient.listRoles()
      assert.isArray(roles)
      assert.deepEqual(roles[0], {
        'id': '1',
        'name': 'authcore.admin',
        'system_role': true
      })
      assert.isTrue(nock.isDone())
    })

    test('should be able to create role', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'CreateRole' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.createRole('testing_application.admin')
      assert.isTrue(nock.isDone())
    })

    test('should be able to delete role', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'DeleteRole' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.deleteRole(5)
      assert.isTrue(nock.isDone())
    })

    test('should be able to assign role', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'AssignRole' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.assignRole(5, 3)
      assert.isTrue(nock.isDone())
    })

    test('should be able to unassign role', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'UnassignRole' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.unassignRole(5, 3)
      assert.isTrue(nock.isDone())
    })

    test('should be able to list role assignments', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListRoleAssignments' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const roles = await authcoreClient.listRoleAssignments(5)
      assert.isArray(roles)
      assert.deepEqual(roles[0], {
        'id': '2',
        'name': 'authcore.admin',
        'system_role': true
      })
      assert.isTrue(nock.isDone())
    })

    test('should be able to list permission assignments', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListPermissionAssignments' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const permissions = await authcoreClient.listPermissionAssignments(1)
      assert.isArray(permissions)
      assert.deepEqual(permissions[0], {
        'name': 'authcore.users.create'
      })
      assert.isTrue(nock.isDone())
    })

    test('should be able to list the permissions of the current user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListCurrentUserPermissions' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const permissions = await authcoreClient.listCurrentUserPermissions()
      assert.isArray(permissions)
      assert.deepEqual(permissions[0], {
        'name': 'authcore.users.create'
      })
      assert.isTrue(nock.isDone())
    })

    test('should be able to create an account', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'CreateUser' },
        { type: 'ChangePassword' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const user = {
        username: 'samuel',
        email: 'samuel@blocksq.com',
        phone: '+85298765432',
        password: 'password',
        displayName: 'Samuel'
      }
      await authcoreClient.createUser(user)
      assert.isTrue(nock.isDone())
    })

    test('should be able to change the password of an user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ChangePassword' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.changePassword('1', 'password')
      assert.isTrue(nock.isDone())
    })

    test('should be able to list sessions of a user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListSessions' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const listSessionsResponse = await authcoreClient.listSessions(1, 10, '', false)
      assert.equal(listSessionsResponse['total_size'], 10)
      assert.exists(listSessionsResponse['sessions'])
      assert.isArray(listSessionsResponse['sessions'])
    })

    test('should be able to delete a given session', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'DeleteSession' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.deleteSession(1)
      assert.isTrue(nock.isDone())
    })

    test('should be able to obtain the user and app metadata for a specified user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'GetMetadata' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const metadata = await authcoreClient.getMetadata(1)
      assert.equal(metadata.userMetadata, '{"favourite_links":["https://github.com","https://blocksq.com"]}')
      assert.equal(metadata.appMetadata, '{"kyc_status":false}')
      assert.isTrue(nock.isDone())
    })

    test('should be able to update the user and app metadata for a specified user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'UpdateMetadata' }
      ])
      // Test
      const authcoreClient = await new AuthCoreManagementClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const metadata = await authcoreClient.updateMetadata(1, '{"favourite_links":["https://github.com","https://blocksq.com"]}', '{ "kyc_status": false }')
      assert.equal(metadata.userMetadata, '{"favourite_links":["https://github.com","https://blocksq.com"]}')
      assert.equal(metadata.appMetadata, '{"kyc_status":false}')
      assert.isTrue(nock.isDone())
    })
  })
})
