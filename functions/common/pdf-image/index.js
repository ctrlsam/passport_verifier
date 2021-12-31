const exec = require('child_process');
const gsExec = './lambda-ghostscript/bin/gs';


const args = [
  "-sDEVICE=png16m", // output png
  "-dNOPAUSE",       // no pause after page
  "-r330",           // 330dpi
  "-q",              // supress output (otherwise will be in output buffer)
  "-o-",             // write to stdout
  "-_"               // read from stdin
];

async function pdfToImage(data) {
  var buffers = [];
  var done = false;

  const gs = exec.spawn(gsExec, args);

  /* Saving output buffers into our array */
  gs.stdout.on('data', data => buffers.push(data) );

  return new Promise((resolve, reject) => {
    /* Finalise output */
    gs.stdout.on('end', () => {
      if (done) return;
      const output = Buffer.concat(buffers);
      buffers = null;
      resolve(output);
    });

    /* Return error, and clean memory */
    gs.stdout.on('error', (err) => {
      done = true;
      buffers = null;
      reject(err);
    });

    /* Write input data */
    gs.stdin.write(data);
    gs.stdin.end();

  });
}

module.exports.pdfToImage = pdfToImage;
