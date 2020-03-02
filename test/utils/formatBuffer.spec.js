/* global suite, test */
const { assert } = require('chai')

const formatBuffer = require('../../src/utils/formatBuffer.js')

const testCases = [{
  // Sanity check
  string: 'Hello world',
  hex: '48656c6c6f20776f726c64',
  base64: 'SGVsbG8gd29ybGQ=',
  base64URLSafe: 'SGVsbG8gd29ybGQ',
  uint8Array: [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100],
  buffer: Buffer.from('Hello world')
}, {
  // URL-safe base64 special character: / <-> _
  string: '???????',
  hex: '3f3f3f3f3f3f3f',
  base64: 'Pz8/Pz8/Pw==',
  base64URLSafe: 'Pz8_Pz8_Pw',
  uint8Array: [63, 63, 63, 63, 63, 63, 63],
  buffer: Buffer.from('???????')
}, {
  // URL-safe base64 special character: + <-> -
  string: '<html><body>Hello world</body></html>',
  hex: '3c68746d6c3e3c626f64793e48656c6c6f20776f726c643c2f626f64793e3c2f68746d6c3e',
  base64: 'PGh0bWw+PGJvZHk+SGVsbG8gd29ybGQ8L2JvZHk+PC9odG1sPg==',
  base64URLSafe: 'PGh0bWw-PGJvZHk-SGVsbG8gd29ybGQ8L2JvZHk-PC9odG1sPg',
  uint8Array: [
    60, 104, 116, 109, 108, 62, 60, 98, 111, 100, 121, 62, 72, 101, 108, 108, 111, 32, 119, 111,
    114, 108, 100, 60, 47, 98, 111, 100, 121, 62, 60, 47, 104, 116, 109, 108, 62
  ],
  buffer: Buffer.from('<html><body>Hello world</body></html>')
}, {
  // Needs to add a prefix-0 for integer-to-hexadecimal conversion
  string: '\n',
  hex: '0a',
  base64: 'Cg==',
  base64URLSafe: 'Cg',
  uint8Array: [10],
  buffer: Buffer.from([10])
}, {
  string: '🤷', // :shrug:
  hex: 'f09fa4b7',
  base64: '8J+ktw==',
  base64URLSafe: '8J-ktw',
  uint8Array: [240, 159, 164, 183],
  buffer: Buffer.from([240, 159, 164, 183])
}, {
  // A long input to test timeout
  string:
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed vitae posuere ipsum. ' +
    'Curabitur efficitur, risus vitae mattis euismod, lectus ligula bibendum nulla, non ' +
    'volutpat tortor tellus non sapien.',
  hex:
    '4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697' +
    '363696e6720656c69742e2053656420766974616520706f737565726520697073756d2e20437572616269747572' +
    '206566666963697475722c207269737573207669746165206d617474697320657569736d6f642c206c656374757' +
    '3206c6967756c6120626962656e64756d206e756c6c612c206e6f6e20766f6c757470617420746f72746f722074' +
    '656c6c7573206e6f6e2073617069656e2e',
  base64:
    'TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gU2VkIHZpdGFlIHB' +
    'vc3VlcmUgaXBzdW0uIEN1cmFiaXR1ciBlZmZpY2l0dXIsIHJpc3VzIHZpdGFlIG1hdHRpcyBldWlzbW9kLCBsZWN0dX' +
    'MgbGlndWxhIGJpYmVuZHVtIG51bGxhLCBub24gdm9sdXRwYXQgdG9ydG9yIHRlbGx1cyBub24gc2FwaWVuLg==',
  base64URLSafe:
    'TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gU2VkIHZpdGFlIHB' +
    'vc3VlcmUgaXBzdW0uIEN1cmFiaXR1ciBlZmZpY2l0dXIsIHJpc3VzIHZpdGFlIG1hdHRpcyBldWlzbW9kLCBsZWN0dX' +
    'MgbGlndWxhIGJpYmVuZHVtIG51bGxhLCBub24gdm9sdXRwYXQgdG9ydG9yIHRlbGx1cyBub24gc2FwaWVuLg',
  uint8Array: [
    76, 111, 114, 101, 109, 32, 105, 112, 115, 117, 109, 32, 100, 111, 108, 111, 114, 32, 115, 105,
    116, 32, 97, 109, 101, 116, 44, 32, 99, 111, 110, 115, 101, 99, 116, 101, 116, 117, 114, 32,
    97, 100, 105, 112, 105, 115, 99, 105, 110, 103, 32, 101, 108, 105, 116, 46, 32, 83, 101, 100,
    32, 118, 105, 116, 97, 101, 32, 112, 111, 115, 117, 101, 114, 101, 32, 105, 112, 115, 117, 109,
    46, 32, 67, 117, 114, 97, 98, 105, 116, 117, 114, 32, 101, 102, 102, 105, 99, 105, 116, 117,
    114, 44, 32, 114, 105, 115, 117, 115, 32, 118, 105, 116, 97, 101, 32, 109, 97, 116, 116, 105,
    115, 32, 101, 117, 105, 115, 109, 111, 100, 44, 32, 108, 101, 99, 116, 117, 115, 32, 108, 105,
    103, 117, 108, 97, 32, 98, 105, 98, 101, 110, 100, 117, 109, 32, 110, 117, 108, 108, 97, 44, 32,
    110, 111, 110, 32, 118, 111, 108, 117, 116, 112, 97, 116, 32, 116, 111, 114, 116, 111, 114, 32,
    116, 101, 108, 108, 117, 115, 32, 110, 111, 110, 32, 115, 97, 112, 105, 101, 110, 46
  ],
  buffer: Buffer.from(
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed vitae posuere ipsum. ' +
    'Curabitur efficitur, risus vitae mattis euismod, lectus ligula bibendum nulla, non ' +
    'volutpat tortor tellus non sapien.'
  )
}]

suite('utils/formatBuffer.js', function () {
  this.slow(1)
  suite('fromString', function () {
    const fn = formatBuffer.fromString
    test('should be able to convert string to buffer correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.string)
        assert.instanceOf(actualOutput, Buffer)
        assert.equal(
          actualOutput.compare(testCase.buffer), 0,
          'The output and the expected buffers are different'
        )
      })
    })
  })
  suite('fromHex', function () {
    const fn = formatBuffer.fromHex
    test('should be able to convert hexadecimal to buffer correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.hex)
        assert.instanceOf(actualOutput, Buffer)
        assert.equal(
          actualOutput.compare(testCase.buffer), 0,
          'The output and the expected buffers are different'
        )
      })
    })
  })
  suite('fromBase64', function () {
    const fn = formatBuffer.fromBase64
    test('should be able to convert base64 to buffer correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.base64)
        assert.instanceOf(actualOutput, Buffer)
        assert.equal(
          actualOutput.compare(testCase.buffer), 0,
          'The output and the expected buffers are different'
        )
      })
    })
  })
  suite('fromBase64URLSafe', function () {
    const fn = formatBuffer.fromBase64URLSafe
    test('should be able to convert URL-safe base64 to buffer correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.base64URLSafe)
        assert.instanceOf(actualOutput, Buffer)
        assert.equal(
          actualOutput.compare(testCase.buffer), 0,
          'The output and the expected buffers are different'
        )
      })
    })
  })
  suite('fromUint8Array', function () {
    const fn = formatBuffer.fromUint8Array
    test('should be able to convert uint8 array to buffer correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.uint8Array)
        assert.instanceOf(actualOutput, Buffer)
        assert.equal(
          actualOutput.compare(testCase.buffer), 0,
          'The output and the expected buffers are different'
        )
      })
    })
  })

  suite('toString', function () {
    const fn = formatBuffer.toString
    test('should be able to convert buffer to string correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.buffer)
        assert.typeOf(actualOutput, 'string')
        assert.equal(actualOutput, testCase.string)
      })
    })
  })
  suite('toHex', function () {
    const fn = formatBuffer.toHex
    test('should be able to convert buffer to hexadecimal correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.buffer)
        assert.typeOf(actualOutput, 'string')
        assert.equal(actualOutput, testCase.hex)
      })
    })
  })
  suite('toBase64', function () {
    const fn = formatBuffer.toBase64
    test('should be able to convert buffer to base64 correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.buffer)
        assert.typeOf(actualOutput, 'string')
        assert.equal(actualOutput, testCase.base64)
      })
    })
  })
  suite('toBase64URLSafe', function () {
    const fn = formatBuffer.toBase64URLSafe
    test('should be able to convert buffer to URL-safe base64 correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.buffer)
        assert.typeOf(actualOutput, 'string')
        assert.equal(actualOutput, testCase.base64URLSafe)
      })
    })
  })
  suite('toUint8Array', function () {
    const fn = formatBuffer.toUint8Array
    test('should be able to convert buffer to uint8 array correctly', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = fn(testCase.buffer)
        assert.typeOf(actualOutput, 'array')
        assert.deepEqual(actualOutput, testCase.uint8Array)
      })
    })
  })
})
