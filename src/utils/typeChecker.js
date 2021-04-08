/**
 * Function returns if the value matches with the type to be checked.
 *
 * @param {undefined|object|boolean|number|string|Function} value Value to be checked.
 * @param {string} type Type to be checked for the value.
 * @param {boolean} required Mode for the type checker. If it is false undefined or null is passed for all types. If it is true only undefined is passed for type of undefined, other cases are rejected. Required mode is for checking whether a field is strictly required or not which undefined/null value is not accepted for that case.
 * @returns {boolean} Matching state of the type of value.
 */
export function typeChecker (value, type, required = false) {
  const validType = [
    'undefined',
    'object',
    'boolean',
    'number',
    'string',
    'function',
    'symbol',
    'bigint'
  ]
  if (typeof required !== 'boolean') {
    throw new Error('required has to be boolean')
  }
  if (!validType.includes(type)) {
    throw new Error('type is invalid, check valid data structure value')
  }
  if (!required) {
    if (value === null || value === undefined) {
      return true
    }
  }
  /* eslint-disable-next-line */
  if (typeof value === type && value !== null) {
    return true
  }
  return false
}
