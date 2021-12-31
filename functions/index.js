const functions = require("firebase-functions");
const express = require("express");
const { router } = require("./api/routes/verify.route");

const app = express();
app.use(express.json());
app.use("/verify", router);

// const port = 3000;
// app.listen(port, () => {
//     console.log(`Verify API listening at http://localhost:${port}`);
// })

const endpoints = functions.region("us-central1").https.onRequest(app);
exports.verify = endpoints;