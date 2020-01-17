// swagger wrapper
const Swagger = require('swagger-client')

const spake2 = require('../crypto/spake2.js')

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
 * @returns {Promise<AuthCoreManagementClient>} The management client.
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
    return new Promise(async (resolve, reject) => { // eslint-disable-line no-async-promise-executor
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @param {string} sortKey The key to be sorted for the list.
   * @param {string} queryKey The key to be queryed for the list.
   * @param {string} queryValue The value to be queryed for the list.
   * @returns {Promise<object>} The list of users.
   */
  async listUsers (pageSize, pageToken, ascending, sortKey = '', queryKey, queryValue) {
    const { ManagementService } = this

    const listUsersResponse = await ManagementService.ListUsers({
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending,
      'sort_key': sortKey,
      'query_key': queryKey,
      'query_value': queryValue
    })
    const listUsersResBody = listUsersResponse.body
    return listUsersResBody
  }

  /**
   * Gets a user.
   *
   * @param {string} userId The ID of the user.
   * @returns {Promise<object>} The user with given ID.
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
   * @returns {Promise<object>} The updated user.
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
   * @returns {Promise<object>} The updated user.
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<object[]>} The list of contacts.
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
   * @returns {Promise<object>} The primary contact object.
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
   * @param {number} contactId The ID of the contact to-be deleted.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<object[]>} The list of second factors.
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
   * @returns {Promise<object>} The list of audit logs.
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
   * @returns {Promise<object>} The list of audit logs.
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
   * @returns {Promise<object[]>} The list of roles.
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
   * @returns {Promise<object>} The role object.
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<object[]>} The list of roles.
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
   * @returns {Promise<object[]>} The list of permissions.
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
   * @returns {Promise<object[]>} The list of permissions.
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
   * @param {object} user The user object.
   * @param {string} user.username The purposed username of the user.
   * @param {string} user.email The purposed email address of the user.
   * @param {string} user.phone The purposed phone number of the user.
   * @param {string} user.password The purposed password of the user.
   * @param {string} user.displayName The purposed display name of the user.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async createUser (user) {
    const { username = '', phone = '', email = '', password } = user
    let { displayName } = user
    if (displayName === undefined || displayName === '') {
      if (username !== '') {
        displayName = username
      } else if (email !== '') {
        displayName = email
      } else if (phone !== '') {
        displayName = phone
      } else {
        throw new Error('displayName cannot be undefined')
      }
    }
    if (password === undefined) {
      throw new Error('no password')
    }
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
    const { salt, verifier } = await spake2.createVerifier(password)
    await ManagementService.ChangePassword({
      'body': {
        'user_id': userId.toString(),
        'password_verifier': {
          'salt': salt,
          'verifierW0': verifier.w0,
          'verifierL': verifier.L
        }
      }
    })
  }

  /**
   * Changes a password of an user.
   *
   * @param {string} userId The user ID.
   * @param {string} newPassword The purposed new password.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async changePassword (userId, newPassword) {
    const { ManagementService } = this

    const { salt, verifier } = await spake2.createVerifier(newPassword)
    await ManagementService.ChangePassword({
      'body': {
        'user_id': userId.toString(),
        'password_verifier': {
          'salt': salt,
          'verifierW0': verifier.w0,
          'verifierL': verifier.L
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
   * @returns {Promise<object[]>} The list of sessions.
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
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
   * @returns {Promise<object>} The metadata of the user.
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
   * @returns {Promise<object>} The updated metadata.
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
   * Lists the OAuth factors for a given user.
   *
   * @param {number} userId The user ID.
   * @returns {Promise<object>} The list of OAuth factors.
   */
  async listOAuthFactors (userId) {
    const { ManagementService } = this
    const listOAuthFactorsResponse = await ManagementService.ListOAuthFactors({
      'user_id': userId
    })
    const listOAuthFactorsResBody = listOAuthFactorsResponse.body
    return listOAuthFactorsResBody['oauth_factors']
  }

  /**
   * Delete an OAuth factor for a given user.
   *
   * @param {number} id The ID of the OAuth factor to-be deleted.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async deleteOAuthFactor (id) {
    const { ManagementService } = this
    await ManagementService.DeleteOAuthFactor({
      'id': id
    })
  }

  /**
   * List templates for email or SMS.
   *
   * @param {string} type The type of templates shall be listed.
   * @returns {Promise<object>} The list of templates.
   */
  async listTemplates (type) {
    const { ManagementService } = this
    const listTemplateResponse = await ManagementService.ListTemplates({
      'type': type
    })
    const listTemplateResBody = listTemplateResponse['body']
    return listTemplateResBody
  }

  /**
   * Get template from type, language and name.
   *
   * @param {string} type The type of templates shall be get.
   * @param {string} language The language of templates shall be get.
   * @param {string} name The name of templates shall be get.
   * @returns {Promise<object>} The result of template.
   */
  async getTemplate (type, language, name) {
    const { ManagementService } = this
    const getTemplateResponse = await ManagementService.GetTemplate({
      'type': type,
      'language': language,
      'name': name
    })
    const getTemplateResBody = getTemplateResponse['body']
    return getTemplateResBody
  }

  /**
   * Create or replace email template.
   *
   * @param {string} language The language of template shall be modified.
   * @param {string} name The name of template shall be modified.
   * @param {string} title The title of template shall be modified.
   * @param {string} htmlTemplate The HTML template shall be modified.
   * @param {string} textTemplate The text template shall be modified.
   */
  async createEmailTemplate (language, name, title, htmlTemplate, textTemplate) {
    const { ManagementService } = this
    await ManagementService.CreateTemplate({
      'body': {
        'template': {
          'language': language,
          'name': name,
          'email_template': {
            'subject': title,
            'html_template': htmlTemplate,
            'text_template': textTemplate
          }
        }
      }
    })
  }

  /**
   * Create or replace SMS template.
   *
   * @param {string} language The language of template shall be modified.
   * @param {string} name The name of template shall be modified.
   * @param {string} template The text template shall be modified.
   */
  async createSMSTemplate (language, name, template) {
    const { ManagementService } = this
    await ManagementService.CreateTemplate({
      'body': {
        'template': {
          'language': language,
          'name': name,
          'sms_template': {
            'template': template
          }
        }
      }
    })
  }

  /**
   * Reset template to be default one.
   *
   * @param {string} type The type of template shall be reset, either email or sms.
   * @param {string} language The language of template shall be reset.
   * @param {string} name The name of template shall be rest.
   */
  async resetTemplate (type, language, name) {
    const { ManagementService } = this
    await ManagementService.ResetTemplate({
      'type': type,
      'language': language,
      'name': name
    })
  }

  /**
   * Constructs management client including interceptor for unauthorized and unauthenticated cases
   * to run callbacks from client implementation.
   *
   * @private
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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
              // For status 401 from api server(Unauthorized in HTTP status), it means unauthenticated in our case
              if (typeof this.config.callbacks.unauthenticated === 'function') {
                this.config.callbacks.unauthenticated()
              }
            }
            if (res.status === 403) {
              // For status 403 from api server(Forbidden in HTTP status), it means unauthorized in our case
              if (typeof this.config.callbacks.unauthorized === 'function') {
                this.config.callbacks.unauthorized()
              }
            }
            return res
          }
        })
          .then(client => {
            this.ManagementService = client.apis.ManagementService
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
