const cbor = require('cbor')
const noise = require('noise-js')

const HANDSHAKE_STATELESS_MAGIC = 'SecretD_Handshake_Stateless_1_0'

class StatelessSession {
  constructor (state, isResponder, authMethod, authParams) {
    this.state = state
    this.isResponder = isResponder
    this.authMethod = authMethod
    this.authParams = authParams
  }

  readMessage (message) {
    var segments = decodeLengthDelimited(message)
    if (segments.length !== 2) {
      throw new Error('cannot decode message')
    }
    if ((this.isResponder && segments[0] !== Buffer.from(HANDSHAKE_STATELESS_MAGIC)) ||
      (!this.isResponder && segments[0].length !== 0)) {
      throw new Error('incorrect magic')
    }
    var payload = this.state.readMessage(segments[1])
    var payloadSegments = decodeLengthDelimited(payload)
    if (payloadSegments.length !== 2) {
      throw new Error('invalid payload')
    }
    if (this.isResponder) {
      this.clientHello = ClientHelloMessage.decode(payloadSegments[0])
      this.remotePublicKey = this.state.e
    }
    return payloadSegments[1]
  }

  writeMessage (payload) {
    var segments = []
    var helloMessage
    if (this.isResponder) {
      segments.push('')
      helloMessage = new ServerHelloMessage(nanosecondTimestamp(), [])
    } else {
      segments.push(Buffer.from(HANDSHAKE_STATELESS_MAGIC))
      helloMessage = new ClientHelloMessage(
        nanosecondTimestamp(),
        this.authMethod,
        this.authParams
      )
    }
    var noisePayload = encodeLengthDelimited([helloMessage.encode(), payload])
    segments.push(this.state.writeMessage(noisePayload))

    return encodeLengthDelimited(segments)
  }

  static initiator (remotePublicKey, localPrivateKey, authMethod, authParams) {
    const negotiationData = Buffer.from(HANDSHAKE_STATELESS_MAGIC)
    const prologue = encodeLengthDelimited([negotiationData])
    var psks = [null, null, Buffer.alloc(32)]
    var state = noise.initialize(
      'IK',
      true,
      prologue,
      localPrivateKey,
      null,
      remotePublicKey,
      null,
      psks
    )
    return new StatelessSession(state, false, authMethod, authParams)
  }

  static responder (localPrivateKey) {
    const negotiationData = Buffer.from(HANDSHAKE_STATELESS_MAGIC)
    const prologue = encodeLengthDelimited([negotiationData])
    var psks = [null, null, Buffer.alloc(32)]
    var state = noise.initialize(
      'IK',
      true,
      prologue,
      localPrivateKey,
      null,
      null,
      null,
      psks
    )
    return new StatelessSession(state, true)
  }
}

class ClientHelloMessage {
  constructor (timestamp, authMethod, authParams) {
    if (typeof timestamp !== 'number' || Math.round(timestamp) !== timestamp) {
      throw new Error('invalid message: timestamp is not a number')
    }
    if (typeof authMethod !== 'string') {
      throw new Error('invalid message: authMethod is not a string')
    }
    if (!Array.isArray(authParams)) {
      throw new Error('invalid message: authParams is not an array')
    }
    this.timestamp = timestamp
    this.authMethod = authMethod
    this.authParams = authParams
  }

  encode () {
    var timestamp = {
      v: this.timestamp,
      encodeCBOR: function (encoder) {
        var shift32 = Math.pow(2, 32)
        return encoder._pushUInt8(27) &&
          encoder._pushUInt32BE(Math.floor(this.v / shift32)) &&
          encoder._pushUInt32BE(this.v % shift32)
      }
    }
    return cbor.encode([timestamp, this.authMethod, this.authParams])
  }

  static decode (message) {
    message = Buffer.from(message)
    var values = cbor.decodeFirstSync(message)
    if (!Array.isArray(values) || values.length !== 3) {
      throw new Error('invalid message: not a tuple of 3 elements')
    }
    return new ClientHelloMessage(...values)
  }
}

class ServerHelloMessage {
  constructor (timestamp, authResult) {
    if (typeof timestamp !== 'number') {
      throw new Error('invalid message: msgid is not a number')
    }
    if (!Array.isArray(authResult)) {
      throw new Error('invalid message: params is not an array')
    }
    this.timestamp = timestamp
    this.authResult = authResult
  }

  encode () {
    return cbor.encode([this.timestamp, this.authResult])
  }

  static decode (message) {
    message = Buffer.from(message)
    var values = cbor.decodeFirstSync(message)
    if (!Array.isArray(values) || values.length !== 2) {
      throw new Error('invalid message: not a tuple of 2 elements')
    }
    return new ServerHelloMessage(...values)
  }
}

/**
 * Split length delimited input in to an array of messages.
 *
 * @private
 * @param {Buffer} data Input buffer.
 * @param {number} offset Number of bytes to skip before starting to read.
 *
 * @returns {[Buffer]} Decoded messages.
 */
function decodeLengthDelimited (data, offset) {
  var output = []
  while (data.length - offset > 2) {
    var len = data.readUInt16BE(offset)
    offset += 2
    if (data.length - offset < len) {
      throw new Error('input is too short')
    }
    output.push(data.slice(offset, offset + len))
    offset += len
  }
  return output
}

/**
 * Encodes an array of messages into length delimited stream.
 *
 * @private
 * @param {[Buffer]} messages An array of messages.
 *
 * @returns {Buffer} Encoded stream.
 */
function encodeLengthDelimited (messages) {
  var outLen = messages.reduce((sum, v) => sum + v.length + 2, 0)
  var buf = Buffer.alloc(outLen)
  var offset = 0
  for (var message of messages) {
    buf.writeUInt16BE(message.length, offset)
    offset += 2
    message.copy(buf, offset)
    offset += message.length
  }
  return buf
}

/**
 * Returns the number of nanoseconds elapsed since epoch.
 *
 * @returns {number} Nanoseconds elapsed since epoch.
 */
function nanosecondTimestamp () {
  var millis = Date.now()
  // it will be higher than Number.MAX_SAFE_INTEGER. We keep using number because we can accept
  // round error in timestamp.
  return millis * 1000000
}

module.exports = {
  StatelessSession
}
