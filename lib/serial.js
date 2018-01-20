/*

 RFC 1982 Serial Number Arithmetic

 Taken from serial-arithmetic module and modified

*/

class SerialNumber {
  constructor(value, size) {
    value = typeof value !== 'undefined' ? value : 0
    size = typeof size !== 'undefined' ? size : 32
    this.serialBits = size
    this.serialBytes = size / 8
    this._value = value
    this._max = Math.pow(2, this.serialBits)
    this._half = Math.pow(2, this.serialBits - 1)
    this._maxAdd = this._half - 1
    this.number = this._value % this._max
  }

  toString() {
    return `<number=${this.number}, bits=${this.serialBits}>`
    // return '' + this.number
  }

  getNumber(options) {
    options = typeof options !== 'undefined' ? options : {}
    options.radix = options.radix ? options.radix : 10
    options.string = options.string !== undefined ? options.string : true

    let number = this.number.toString(options.radix)

    if (options.encoding === 'BE') {
      let buf = new Buffer(this.serialBytes)
      buf.writeUIntLE(this.number, 0, this.serialBytes)
      number = buf.readUIntBE(0, this.serialBytes).toString(options.radix)
    }

    if (options.string) {
      return number
    } else {
      console.log(number)
      return parseInt(number, options.radix)
    }
  }

  eq(that) {
    return this.number === that.number
  }

  ne(that) {
    return this.number !== that.number
  }

  lt(that) {
    return (
      (this.number < that.number && that.number - this.number < this._half) ||
      (this.number > that.number && this.number - that.number > this._half)
    )
  }

  gt(that) {
    return (
      (this.number < that.number && that.number - this.number > this._half) ||
      (this.number > that.number && this.number - that.number < this._half)
    )
  }

  le(that) {
    return this.eq(that) || this.lt(that)
  }

  ge(that) {
    return this.eq(that) || this.gt(that)
  }

  delta(that) {
    let result = this.number - that.number
    if (result < 0 && result < -this._half) result += this._max
    return result
  }

  inc(delta) {
    this.number = (this.number + delta) % this._max
    return this
  }

  copy() {
    return new SerialNumber(this.number, this.serialBits)
  }

  prev() {
    return new SerialNumber(
      this.number === 0 ? this._max : this.number - 1,
      this.serialBits
    )
  }

  next() {
    return new SerialNumber(
      this.number === this._max ? 0 : this.number + 1,
      this.serialBits
    )
  }
}

module.exports = function(value, size) {
  return new SerialNumber(value, size)
}
