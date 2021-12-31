const maxFileSize = 5; // mb

const isFileTooBig = (buffer) => {
    const mb = Buffer.byteLength(buffer) / 1000000;
    return mb > maxFileSize;
};

module.exports = { isFileTooBig };