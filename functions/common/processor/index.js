const { pdfToImage } = require("../pdf-image/index");
const { qrDecode } = require("../qr-code/index");
const { verifier } = require("../verify/index");

async function pdf(pdfBuffer) {
  let imageBuffer;

  try {
    imageBuffer = await pdfToImage(pdfBuffer);
  } catch (e) { console.log(e); }

  if (!imageBuffer) return { error: 'Failed read PDF' }

  return qrCode(imageBuffer);
}

async function qrCode(imageBuffer) {
  let payload;

  try {
    payload = await qrDecode(imageBuffer);
  } catch (e) { console.log(e); }

  if (!payload) return { error: 'Failed read QR data' }

  return verify(payload);
}

async function verify(payload) {
  let passport;

  try {
    passport = await verifier(payload);
  } catch (e) { console.log(e); }

  if (!passport) return { error: 'Could not verify, likely not a COVID passport'}
  return passport;
}

module.exports.pdf = pdf;
module.exports.qrCode = qrCode;
module.exports.verify = verify;
