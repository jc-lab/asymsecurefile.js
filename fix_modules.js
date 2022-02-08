const path = require('path');
const fs = require('fs');
const child_process = require('child_process');

if (process.env['npm_command']) {
  child_process.execSync('npm dedupe', {
    stdio: 'inherit'
  });
}

try {
  fs.rmdirSync(path.resolve('./node_modules/pkijs/node_modules'), {
    recursive: true
  });
} catch (e) {
  console.error(e);
}

try {
  const file = path.resolve(__dirname, './node_modules/@types/asn1js');
  if (fs.existsSync(file)) {
    fs.rmdirSync(file, {
      recursive: true
    });
  }
} catch (e) {
  console.error(e);
}
