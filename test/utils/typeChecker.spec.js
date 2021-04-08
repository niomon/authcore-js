/* global suite, test */
const { assert } = require('chai')

const { typeChecker } = require('../../src/utils/typeChecker.js')

const testCases = [{
  value: ['1'],
  type: 'undefined',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: ['1'],
  type: 'object',
  expectedResult: true,
  expectedRequiredResult: true
}, {
  value: ['1'],
  type: 'boolean',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: ['1'],
  type: 'number',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: ['1'],
  type: 'string',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: ['1'],
  type: 'function',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: ['1'],
  type: 'symbol',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: ['1'],
  type: 'bigint',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: {
    key: 'value'
  },
  type: 'undefined',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: {
    key: 'value'
  },
  type: 'object',
  expectedResult: true,
  expectedRequiredResult: true
}, {
  value: {
    key: 'value'
  },
  type: 'boolean',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: {
    key: 'value'
  },
  type: 'number',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: {
    key: 'value'
  },
  type: 'string',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: {
    key: 'value'
  },
  type: 'function',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: {
    key: 'value'
  },
  type: 'symbol',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: {
    key: 'value'
  },
  type: 'bigint',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: true,
  type: 'object',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: true,
  type: 'boolean',
  expectedResult: true,
  expectedRequiredResult: true
}, {
  value: false,
  type: 'boolean',
  expectedResult: true,
  expectedRequiredResult: true
}, {
  value: true,
  type: 'number',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: true,
  type: 'string',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: true,
  type: 'function',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: true,
  type: 'symbol',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: true,
  type: 'bigint',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: 1,
  type: 'undefined',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: 1,
  type: 'object',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: 1,
  type: 'boolean',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: 1,
  type: 'number',
  expectedResult: true,
  expectedRequiredResult: true
}, {
  value: 1,
  type: 'string',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: 1,
  type: 'function',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: 1,
  type: 'symbol',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: 'a',
  type: 'bigint',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: () => {},
  type: 'undefined',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: () => {},
  type: 'object',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: () => {},
  type: 'boolean',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: () => {},
  type: 'number',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: () => {},
  type: 'string',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: () => {},
  type: 'function',
  expectedResult: true,
  expectedRequiredResult: true
}, {
  value: () => {},
  type: 'symbol',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: () => {},
  type: 'bigint',
  expectedResult: false,
  expectedRequiredResult: false
}, {
  value: undefined,
  type: 'undefined',
  expectedResult: true,
  expectedRequiredResult: true
}, {
  value: undefined,
  type: 'object',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: undefined,
  type: 'boolean',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: undefined,
  type: 'number',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: undefined,
  type: 'string',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: undefined,
  type: 'function',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: undefined,
  type: 'symbol',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: undefined,
  type: 'bigint',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'undefined',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'object',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'boolean',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'number',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'string',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'function',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'symbol',
  expectedResult: true,
  expectedRequiredResult: false
}, {
  value: null,
  type: 'bigint',
  expectedResult: true,
  expectedRequiredResult: false
}]

suite('utils/typeChecker.js', function () {
  suite('typeChecker', function () {
    test('should be able to return the type is true or not', function () {
      testCases.forEach(function (testCase) {
        const actualOutput = typeChecker(testCase.value, testCase.type)
        assert.equal(
          actualOutput,
          testCase.expectedResult,
          `Test case with value ${testCase.value}, type ${testCase.type} is not expected.`
        )
      })
    })
    test('should be able to return required type is true or not', function () {
      testCases.forEach(function (testCase) {
        const actualRequiredOutput = typeChecker(testCase.value, testCase.type, true)
        assert.equal(
          actualRequiredOutput,
          testCase.expectedRequiredResult,
          `Test case for required with value ${testCase.value}, type ${testCase.type} is not expected.`
        )
      })
    })
  })
})
