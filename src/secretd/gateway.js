const cbor = require('cbor')
const axios = require('axios')
const noise = require('noise-js')
const { StatelessSession } = require('./session')

class SecretdGatewayClient {
  constructor (config) {
    if (!config.accessToken) {
      throw new Error('missing accessToken')
    }
    if (!config.apiBaseURL) {
      throw new Error('missing apiBaseURL')
    }
    this.accessToken = config.accessToken
    this.http = axios.create({
      baseURL: this.apiBaseURL,
      timeout: 30000,
      headers: {
        'Authorization': `Bearer ${this.accessToken}`
      }
    })
  }

  async getInfo () {
    var resp = await this.http.get('/api/secretdgateway/info')
    return resp.data
  }

  async sendRequest (method, params) {
    var info = await this.getInfo()
    var clusterIdentity = Buffer.from(info['cluster_identity'], 'base64')
    var localKeypair = noise.generateKeypair()
    var session = StatelessSession.initiator(
      clusterIdentity,
      localKeypair.secretKey,
      'authcore',
      [this.accessToken]
    )
    var req = new RequestMessage(0, method, params)
    var reqmsg = session.writeMessage(req.encode())
    var respmsg = await this.forward(reqmsg)
    var resp = ResponseMessage.decode(session.readMessage(respmsg))
    if (resp.error) {
      console.error('secretd returned an error', resp.error)
      throw new Error(JSON.stringify(resp.error))
    }
    return resp['result']
  }

  async forward (reqmsg) {
    var body = {
      'request_message': reqmsg.toString('base64')
    }
    var resp = await this.http.post('/api/secretdgateway/forward', body)
    var respmsg = resp.data['response_message']
    return Buffer.from(respmsg, 'base64')
  }
}

class RequestMessage {
  constructor (msgid, method, params) {
    if (typeof msgid !== 'number') {
      throw new Error('invalid message: msgid is not a number')
    }
    if (typeof method !== 'string') {
      throw new Error('invalid message: method is not a string')
    }
    if (!Array.isArray(params)) {
      throw new Error('invalid message: params is not an array')
    }
    this.msgid = msgid
    this.method = method
    this.params = params
  }

  encode () {
    return cbor.encode([0, this.msgid, this.method, this.params])
  }

  static decode (message) {
    message = Buffer.from(message)
    var values = cbor.decodeFirstSync(message)
    if (!Array.isArray(values) || values.length !== 4) {
      throw new Error('invalid message: not a tuple of 4 elements')
    }
    var type = values.shift()
    if (type !== 0) {
      throw new Error('not a request message')
    }
    return new RequestMessage(...values)
  }
}

class ResponseMessage {
  constructor (msgid, error, result) {
    if (typeof msgid !== 'number') {
      throw new Error('invalid message: msgid is not a number')
    }
    this.msgid = msgid
    this.error = error
    this.result = result
  }

  encode () {
    return cbor.encode([1, this.msgid, this.error, this.result])
  }

  static decode (message) {
    message = Buffer.from(message)
    var values = cbor.decodeFirstSync(message)
    if (!Array.isArray(values) || values.length !== 4) {
      throw new Error('invalid message: not a tuple of 4 elements')
    }
    var type = values.shift()
    if (type !== 1) {
      throw new Error('not a response message')
    }
    return new ResponseMessage(...values)
  }
}

module.exports = {
  SecretdGatewayClient
}
