/*

 https://en.wikipedia.org/wiki/Cyclic_redundancy_check

 Algorithms ported from https://pycrc.org/

*/

class CRC {
  constructor(width, poly, xor_in, xor_out, reflect) {
    this.width = width
    this.poly = poly
    this.xor_in = xor_in
    this.xor_out = xor_out
    this.reflect = reflect
    this.msb_mask = 1 << (this.width - 1)
    this.mask = ((this.msb_mask - 1) << 1) | 1
    this.crc_shift = this.width < 8 ? 8 - this.width : 0
    let table = this.gen_table()
    this.table = table

    // optimized for crc32c
    if (width === 32 && reflect && xor_in === 0xffffffff && xor_out === 0xffffffff) {
      this.calculate = function (buffer) {
        buffer = preprocess(buffer)
        let crc = -1
        for (let i = 0; i < buffer.length; i++)
          crc = table[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8)
        return (crc ^ -1) >>> 0
      }
    }
  }

  calculate(buffer) {
    buffer = preprocess(buffer)
    let crc
    if (this.reflect) {
      crc = this.xor_in === 0xffffffff ? -1 : reflect(this.xor_in, this.width)
      for (let i = 0; i < buffer.length; i++) {
        let key = (crc ^ buffer[i]) & 0xff
        crc = (this.table[key] ^ (crc >>> 8)) & this.mask
      }
    } else {
      crc = this.xor_in << this.crc_shift
      for (let i = 0; i < buffer.length; i++) {
        let key = ((crc >> (this.width - 8 + this.crc_shift)) ^ buffer[i]) & 0xff
        crc <<= 8 - this.crc_shift
        crc ^= this.table[key] << this.crc_shift
        crc &= this.mask << this.crc_shift
      }
      crc >>= this.crc_shift
    }
    crc ^= this.xor_out
    return crc >>> 0
  }

  calculate_no_table(buffer) {
    buffer = preprocess(buffer)
    let crc = this.xor_in
    for (let i = 0; i < buffer.length; i++) {
      let octet = buffer[i]
      if (this.reflect) octet = reflect(octet, 8)
      for (let i = 0; i < 8; i++) {
        let topbit = crc & this.msb_mask
        if (octet & (0x80 >> i)) topbit ^= this.msb_mask
        crc <<= 1
        if (topbit) crc ^= this.poly
      }
      crc &= this.mask
    }
    if (this.reflect) crc = reflect(crc, this.width)
    crc ^= this.xor_out
    return crc >>> 0
  }

  gen_table() {
    let table_length = 256
    let table = []
    for (let i = 0; i < table_length; i++) {
      let reg = i
      if (this.reflect) reg = reflect(reg, 8)
      reg = reg << (this.width - 8 + this.crc_shift)
      for (let j = 0; j < 8; j++) {
        if ((reg & (this.msb_mask << this.crc_shift)) !== 0) {
          reg <<= 1
          reg ^= this.poly << this.crc_shift
        } else {
          reg <<= 1
        }
      }
      if (this.reflect) reg = reflect(reg >> this.crc_shift, this.width) << this.crc_shift
      reg = (reg >> this.crc_shift) & this.mask
      table[i] = reg >>> 0
    }
    return table
  }

  print() {
    let table = this.table
    let digits = Math.ceil(this.width / 4)
    let shift = (digits < 4) ? 4 : 3
    let rows = table.length >> shift
    let columns = 1 << shift
    let result = ''
    for (let r = 0; r < rows; r++) {
      let row = ''
      for (let c = 0; c < columns; c++) {
        let val = table[r << shift | c]
        val = '000000000' + val.toString(16)
        val = val.substr(val.length - digits)
        row += '0x' + val + ', '
      }
      result += '  ' + row + '\n'
    }
    result = '[\n' + result.slice(0, -3) + '\n]'
    return result
  }

}


function preprocess(data) {
  if (Buffer.isBuffer(data)) return data
  switch (typeof data) {
    case 'number':
      let buffer = Buffer.alloc(4)
      buffer.writeUInt32BE(data)
      return buffer
    case 'string':
      return Buffer.from(data)
    default:
      throw new Error()
  }
}


function reflect(data, width) {
  let res = 0
  for (let i = 0; i < width; i++) {
    res = res << 1 | data & 1
    data >>= 1
  }
  return res
}


module.exports = {
  CRC,
  crc6: new CRC(6, 0x2F),
  crc8: new CRC(8, 0x07),
  crc10: new CRC(10, 0x233),
  crc32: new CRC(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true),
  crc32c: new CRC(32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true)
}
