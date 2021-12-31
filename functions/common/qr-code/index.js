const jsQR = require("jsqr");
const Jimp = require("jimp");

/**
 * Decodes image buffer of QR code to get data
 * @param {*} buffer image bytes
 * @return QR code data
 */
async function qrDecode(buffer) {
  const img = await Jimp.read(buffer);
  const {bitmap: {width, height, data}} = img;

  const code = jsQR(data, width, height);
  return code.data;
}

module.exports.qrDecode = qrDecode;
