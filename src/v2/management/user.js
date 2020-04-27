const basePath = '/api/v2'

class UserAPI {
  constructor (authcore) {
    this.authcore = authcore
  }

  async listUserEvents (userId, pageToken, rowsPerPage, order, options) {
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
}

export default UserAPI
