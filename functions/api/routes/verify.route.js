const express = require("express");
const fileParser = require("express-multipart-file-parser");
const {pdf, qrCode, verify} = require("../../common/processor/index");
const { isFileTooBig } = require("../util/max-file-size");

const router = express.Router();

/**
 * Root folder response
 */
router.all("/", async (req, res) => {
  return res.status(400).send({error: "append verify type to url"});
});

// middleware
router.use(fileParser);

/**
 * PDF verify endpoint
 */
router.all("/pdf", async (req, res) => {

  if (!req.files)
    return res.status(400).send({error: "pdf not uploaded"});

  const { mimetype, buffer } = req.files[0];

  if (mimetype !== "application/pdf")
    return res.status(400).send({error: "file is not of type PDF"});

  if (isFileTooBig(buffer))
    return res.status(400).send({error: "file is too big (5mb max)"});

  const output = await pdf(buffer);
  if (output) return res.status(200).send(output);

  return res.status(400).send({error: "something went wrong"});
});

/**
 * Image verify endpoint
 */
router.all("/image", async (req, res) => {
  if (!req.files)
    return res.send({error: "image not uploaded"});

  const { mimetype, buffer } = req.files[0];

  if (!mimetype.startsWith("image/"))
    return res.status(400).send({error: "file is not an image"});

  if (isFileTooBig(buffer))
    return res.status(400).send({error: "file is too big (5mb max)"});

  const output = await qrCode(buffer);
  if (output) return res.status(200).send(output);

  return res.status(400).send({error: "something went wrong"});
});

/**
 * Text verify endpoint
 */
router.all("/text", async (req, res) => {
  const {qr_content} = req.body;
  if (!qr_content)
    return res.status(400).send({error: "qr_content not provided"});

  const output = await verify(qr_content);
  if (output) return res.status(200).send(output);
  return res.status(400).send({error: "something went wrong"});
});


exports.router = router;
