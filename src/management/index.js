// swagger wrapper
const Swagger = require('swagger-client')

const srp = require('../crypto/srp.js')
const { scrypt } = require('../crypto/scrypt.js')
const formatBuffer = require('../utils/formatBuffer.js')
const unicodeNorm = require('../utils/unicodeNorm.js')

/**
 * The class interacting between web client and AuthCore ManagementAPI server.
 * 
 * @public
 * @param {object} config
 * @param {string} config.apiBaseURL The base URL for the Authcore instance.
 * @param {object} config.callbacks The set of callback functions to-be called.
 * @param {Function} config.callbacks.unauthenticated The callback function when a user is
 *        unauthenticated.
 * @param {string} config.accessToken The access token of the user.
 * @example
 * const mgmtClient = await new AuthCoreManagementClient({
 *   apiBaseURL: 'https://auth.example.com',
 *   callbacks: {
 *     unauthenticated: function () {
 *       alert('unauthenticated!')
 *     }
 *   },
 *   accessToken: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJle...'
 * })
 */
class AuthCoreManagementClient {
  constructor (config) {
    return new Promise(async (resolve, reject) => {
      this.config = config

      // Set accessToken into API
      await this.setAccessToken(config.accessToken)

      resolve(this)
    })
  }

  /**
   * Sets the access token and refreshes the Swagger client.
   * 
   * @public
   * @param {string} accessToken The access token of the user.
   */
  async setAccessToken (accessToken) {
    this.config.accessToken = accessToken
    await this._getSwaggerClient()
  }

  /**
   * Gets the access token.
   * 
   * @public
   * @returns {string} The access token of the user.
   */
  getAccessToken () {
    return this.config.accessToken
  }

  // Management APIs

  /**
   * Lists the users.
   *
   * @param {number} pageSize The number of users per page.
   * @param {string} pageToken The page token.
   * @param {boolean} ascending Boolean flag indicating the order of the users.
   * @returns {object} The list of users.
   */
  async listUsers (pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listUsersResponse = await ManagementService.ListUsers({
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listUsersResBody = listUsersResponse.body
    return listUsersResBody
  }

  /**
   * Gets a user.
   *
   * @param {string} userId The ID of the user.
   * @returns {object} The user with given ID.
   */
  async getUser (userId) {
    const { ManagementService } = this

    const getUserResponse = await ManagementService.GetUser({
      'user_id': userId.toString()
    })
    const getUserResBody = getUserResponse.body
    return getUserResBody
  }

  /**
   * Updates a user.
   *
   * @param {string} userId The ID of the user.
   * @param {object} userObject The purposed update for the user.
   * @returns {object} The updated user.
   */
  async updateUserProfile (userId, userObject) {
    const { ManagementService } = this

    const updateUserResponse = await ManagementService.UpdateUser({
      'user_id': userId,
      'body': {
        'user': userObject
      }
    })
    const updateUserResBody = updateUserResponse.body
    return updateUserResBody
  }

  /**
   * Updates the lock status of a user.
   *
   * @param {string} userId The ID of the user.
   * @param {boolean} locked Boolean flag indicating if the user will be locked.
   * @param {number} lockInDays The number of days locked.
   * @param {string} description A description for the lock (or unlock).
   * @returns {object} The updated user.
   */
  async updateUserLock (userId, locked, lockInDays, description) {
    const { ManagementService } = this

    let lockExpiredAt
    if (locked) {
      if (lockInDays === Infinity) {
        lockExpiredAt = '2038-01-19T00:00:00Z'
      } else if (parseFloat(lockInDays) > 0) {
        lockExpiredAt = new Date(new Date().getTime() + 86400000 * parseFloat(lockInDays)).toISOString()
      } else {
        throw new Error('lock in days should be positive')
      }
    }

    const updateUserResponse = await ManagementService.UpdateUser({
      'user_id': userId,
      'body': {
        'user': {
          'locked': locked,
          'lock_expired_at': lockExpiredAt,
          'lock_description': description
        },
        'type': 'LOCK'
      }
    })
    const updateUserResBody = updateUserResponse.body
    return updateUserResBody
  }

  /**
   * Creates an email contact of a user.
   *
   * @param {string} userId The ID of the user.
   * @param {string} email The e-mail address to be created as a contact.
   */
  async createEmailContact (userId, email) {
    const { ManagementService } = this

    const createContactResponse = await ManagementService.CreateContact({
      'user_id': userId,
      'body': {
        'contact': {
          'type': 'EMAIL',
          'value': email
        }
      }
    })
    const createContactResBody = createContactResponse.body
    await ManagementService.StartVerifyContact({
      body: {
        'contact_id': createContactResBody['id']
      }
    })
  }

  /**
   * Creates a phone contact of a user.
   *
   * @param {string} userId The ID of the user.
   * @param {string} phone The phone number to be created as a contact.
   */
  async createPhoneContact (userId, phone) {
    const { ManagementService } = this

    const createContactResponse = await ManagementService.CreateContact({
      'user_id': userId,
      'body': {
        'contact': {
          'type': 'PHONE',
          'value': phone
        }
      }
    })
    const createContactResBody = createContactResponse.body
    await ManagementService.StartVerifyContact({
      body: {
        'contact_id': createContactResBody['id']
      }
    })
  }

  /**
   * Lists the contacts for a user.
   *
   * @param {string} userId The user ID.
   * @param {string} type The type of contacts, either `phone` or `email`. (Optional).
   * @returns {object[]} The list of contacts.
   */
  async listContacts (userId, type) {
    const { ManagementService } = this

    const listContactsResponse = await ManagementService.ListContacts({
      'user_id': userId,
      type: type
    })
    const listContactsResBody = listContactsResponse.body
    return listContactsResBody
  }

  /**
   * Changes the primary contact of a user.
   *
   * @param {string} contactId The ID of the new primary contact.
   * @returns {object} The primary contact object.
   */
  async updatePrimaryContact (contactId) {
    const { ManagementService } = this

    const updatePrimaryContactResponse = await ManagementService.UpdatePrimaryContact({
      'contact_id': contactId
    })
    const updatePrimaryContactResBody = updatePrimaryContactResponse.body
    return updatePrimaryContactResBody
  }

  /**
   * Deletes a contact.
   *
   * @param {number} contactId The ID of the contact to-be deleted..
   */
  async deleteContact (contactId) {
    const { ManagementService } = this

    await ManagementService.DeleteContact({
      'contact_id': contactId
    })
  }

  /**
   * Starts to verify an owned contact by requesting a verification email / SMS.
   *
   * @param {string} contactId The ID of the contact to-be verified.
   */
  async startVerifyContact (contactId) {
    const { ManagementService } = this
    await ManagementService.StartVerifyContact({
      'contact_id': (contactId).toString()
    })
  }

  /**
   * Lists the second factors for a user.
   *
   * @param {string} id The user ID.
   * @returns {object[]} The list of second factors.
   */
  async listSecondFactors (id) {
    const { ManagementService } = this

    const listSecondFactorsResponse = await ManagementService.ListSecondFactors({
      'user_id': id.toString()
    })
    const listSecondFactorsResBody = listSecondFactorsResponse.body
    return listSecondFactorsResBody['second_factors']
  }

  /**
   * Lists the audit logs.
   *
   * @param {number} pageSize The number of audit logs per page.
   * @param {string} pageToken The page token.
   * @param {boolean} ascending Boolean flag indicating the order of the audit logs.
   * @returns {object} The list of audit logs.
   */
  async listAuditLogs (pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listAuditLogsResponse = await ManagementService.ListAuditLogs({
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listAuditLogsResBody = listAuditLogsResponse.body
    return listAuditLogsResBody
  }

  /**
   * Lists the audit logs of a user.
   *
   * @param {string} userId The user ID.
   * @param {number} pageSize The number of audit logs per page.
   * @param {string} pageToken The page token.
   * @param {boolean} ascending Boolean flag indicating the order of the audit logs.
   * @returns {object} The list of audit logs.
   */
  async listUserAuditLogs (userId, pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listUserAuditLogsResponse = await ManagementService.ListAuditLogs({
      'user_id': userId,
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listUserAuditLogsResBody = listUserAuditLogsResponse.body
    return listUserAuditLogsResBody
  }

  /**
   * List the roles.
   *
   * @returns {object[]} The list of roles.
   */
  async listRoles () {
    const { ManagementService } = this

    const listRolesResponse = await ManagementService.ListRoles()
    const listRolesResBody = listRolesResponse.body
    return listRolesResBody['roles']
  }

  /**
   * Creates a new role.
   * 
   * @param {string} name The name of the role.
   * @returns {object} The role object.
   */
  async createRole (name) {
    const { ManagementService } = this

    const createRoleResponse = await ManagementService.CreateRole({
      'body': {
        'name': name
      }
    })
    const createRoleResBody = createRoleResponse.body
    return createRoleResBody
  }

  /**
   * Deletes a role.
   * 
   * @param {string} roleId The ID of the role to-be deleted.
   */
  async deleteRole (roleId) {
    const { ManagementService } = this
    await ManagementService.DeleteRole({
      'role_id': roleId
    })
  }

  /**
   * Assigns the specified role to the given user.
   * 
   * @param {string} userId The user ID.
   * @param {string} roleId The role ID.
   */
  async assignRole (userId, roleId) {
    const { ManagementService } = this
    await ManagementService.AssignRole({
      'user_id': userId,
      'body': {
        'role_id': roleId.toString()
      }
    })
  }

  /**
   * Unassigns the specified role from the given user.
   * 
   * @param {string} userId The user ID.
   * @param {string} roleId The role ID.
   */
  async unassignRole (userId, roleId) {
    const { ManagementService } = this
    await ManagementService.UnassignRole({
      'user_id': userId,
      'role_id': roleId
    })
  }

  /**
   * Lists the roles of a user.
   *
   * @param {string} userId The user ID.
   * @returns {object[]} The list of roles.
   */
  async listRoleAssignments (userId) {
    const { ManagementService } = this

    const listRoleAssignmentsResponse = await ManagementService.ListRoleAssignments({
      'user_id': userId
    })
    const listRoleAssignmentsResBody = listRoleAssignmentsResponse.body
    return listRoleAssignmentsResBody['roles']
  }

  /**
   * Lists of permissions for a role.
   *
   * @param {string} roleId The role ID.
   * @returns {object[]} The list of permissions.
   */
  async listPermissionAssignments (roleId) {
    const { ManagementService } = this

    const listPermissionAssignmentsResponse = await ManagementService.ListPermissionAssignments({
      'role_id': roleId
    })
    const listPermissionAssignmentsResBody = listPermissionAssignmentsResponse.body
    return listPermissionAssignmentsResBody['permissions']
  }

  /**
   * Lists the permissions of the current user.
   *
   * @returns {object[]} The list of permissions.
   */
  async listCurrentUserPermissions () {
    const { ManagementService } = this

    const listCurrentUserPermissionsResponse = await ManagementService.ListCurrentUserPermissions()
    const listCurrentUserPermissionsResBody = listCurrentUserPermissionsResponse.body
    return listCurrentUserPermissionsResBody['permissions']
  }

  /**
   * Creates an user.
   *
   * @param {string} username The purposed username of the user.
   * @param {string} password The purposed password of the user.
   * @param {string} email The purposed email address of the user.
   * @param {string} phone The purposed phone number of the user.
   * @param {string} displayName The purposed display name of the user.
   */
  async createUser (username, password, email, phone, displayName) {
    const { ManagementService } = this

    // Step 1: Create a user
    const createUserResponse = await ManagementService.CreateUser({
      'body': {
        'username': username,
        'email': email,
        'phone': phone,
        'display_name': displayName
      }
    })
    const createUserResBody = createUserResponse.body
    const userId = createUserResBody['user']['id']

    // Step 2: Change the password of the created user
    const hashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(password)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { salt, verifier } = await srp.createVerifier(username, hashedPassword)
    await ManagementService.ChangePassword({
      'body': {
        'user_id': userId.toString(),
        'password_verifier': {
          'salt': formatBuffer.toBase64(salt),
          'verifier': formatBuffer.toBase64(verifier)
        }
      }
    })
  }

  /**
   * Changes a password of an user.
   *
   * @param {string} userId The user ID.
   * @param {string} newPassword The purposed new password.
   */
  async changePassword (userId, newPassword) {
    const { ManagementService } = this

    const { username } = await this.getUser(userId)
    const newHashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(newPassword)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { salt, verifier } = await srp.createVerifier(username, newHashedPassword)
    await ManagementService.ChangePassword({
      'body': {
        'user_id': userId.toString(),
        'password_verifier': {
          'salt': formatBuffer.toBase64(salt),
          'verifier': formatBuffer.toBase64(verifier)
        }
      }
    })
  }

  /**
   * Lists the sessions of a user.
   *
   * @param {string} userId The user ID.
   * @param {number} pageSize The number of sessions per page.
   * @param {string} pageToken The page token.
   * @param {boolean} ascending Boolean flag indicating the order of the sessions.
   * @returns {object[]} The list of sessions.
   */
  async listSessions (userId, pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listSessionsResponse = await ManagementService.ListSessions({
      'user_id': userId,
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listSessionsResBody = listSessionsResponse.body
    return listSessionsResBody
  }

  /**
   * Deletes a session.
   *
   * @param {number} sessionId The session ID to-be deleted.
   */
  async deleteSession (sessionId) {
    const { ManagementService } = this
    await ManagementService.DeleteSession({
      'session_id': sessionId
    })
  }

  /**
   * Gets the metadata of a user.
   *
   * @param {number} userId The user ID.
   * @returns {string} The metadata of the user.
   */
  async getMetadata (userId) {
    const { ManagementService } = this

    const getMetadataResponse = await ManagementService.GetMetadata({
      'user_id': userId
    })
    const getMetadataResBody = getMetadataResponse.body
    return {
      userMetadata: getMetadataResBody['user_metadata'],
      appMetadata: getMetadataResBody['app_metadata']
    }
  }

  /**
   * Updates the metadata for a given user.
   *
   * @param {number} userId The user ID.
   * @param {string} userMetadata The purposed user metadata.
   * @param {string} appMetadata The purposed app metadata.
   * @returns {object} The updated metadata.
   */
  async updateMetadata (userId, userMetadata, appMetadata) {
    const { ManagementService } = this
    const updateMetadataResponse = await ManagementService.UpdateMetadata({
      'user_id': userId,
      'body': {
        'user_metadata': userMetadata,
        'app_metadata': appMetadata
      }
    })
    const updateMetadataResBody = updateMetadataResponse.body
    return {
      userMetadata: updateMetadataResBody['user_metadata'],
      appMetadata: updateMetadataResBody['app_metadata']
    }
  }

  /**
   * Constructs management client including interceptor for unauthorized and unauthenticated cases
   * to run callbacks from client implementation.
   *
   * @private
   */
  async _getSwaggerClient () {
    let authorizations
    if (this.config.accessToken) {
      authorizations = {
        'BearerAuth': {
          'value': `Bearer ${this.config.accessToken}`
        }
      }
    }

    if (this.config !== undefined) {
      await new Promise((resolve, reject) => {
        const swaggerJsonURL = `${this.config.apiBaseURL}/api/managementapi/management.swagger.json`
        Swagger({
          url: swaggerJsonURL,
          authorizations,
          requestInterceptor: (req) => {
            // Hijack the scheme to match the origin request
            const schemePos = req.url.indexOf(':')
            const urlWithoutScheme = req.url.slice(schemePos)
            req.url = this.config.apiBaseURL.split(':')[0] + urlWithoutScheme
            return req
          },
          responseInterceptor: (res) => {
            if (res.status === 401) {
              this.config.callbacks['unauthorized']()
            }
            if (res.status === 403) {
              this.config.callbacks['unauthenticated']()
            }
            return res
          }
        })
          .then(client => {
            // Flat the APIs from the tag to become ManagementService
            let apiValue = Object.values(client.apis)
            let apiResult = apiValue.reduce((apis, api) => {
              apis = Object.assign(apis, api)
              return apis
            }, {})
            this.ManagementService = apiResult
            resolve(client.apis)
          })
          .catch(err => {
            return reject(err)
          })
      })
    }
  }
}

exports.AuthCoreManagementClient = AuthCoreManagementClient
