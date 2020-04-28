const basePath = '/api/v2'

class UserAPI {
  constructor (authcore) {
    this.authcore = authcore
  }

  /**
   * List the event logs of a user from user ID.
   *
   * @param {number} userId The user's ID.
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {number} rowsPerPage The number of events returns in a page.
   * @param {string} order The order of the result returned.
   * @returns {object} Result including the event logs list, page token for previous and next page and number of total items.
   */
  async listUserEvents (userId, pageToken, rowsPerPage, order) {
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    if ((pageToken !== undefined && pageToken !== null) && typeof pageToken !== 'string') {
      throw new Error('pageToken has to be in string format')
    }
    const params = new URLSearchParams()
    params.append('user_id', userId)
    params.append('limit', rowsPerPage)
    params.append('page_token', pageToken)
    params.append('order', order)
    const url = new URL(basePath + '/audit_logs?' + params.toString(), this.authcore.baseURL)
    const resp = await this.authcore._http.get(url.toString())
    return resp.data
  }

  /**
   * Delete a user from user ID.
   *
   * @param {number} userId The user's ID.
   */
  async deleteUser (userId) {
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    const url = new URL(basePath + '/users/' + userId, this.authcore.baseURL)
    await this.authcore._http.delete(url)
  }
}

export default UserAPI
