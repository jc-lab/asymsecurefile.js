const path = require('path');
const fs = require('fs');

try {
    fs.rmdirSync(path.resolve('./node_modules/pkijs/node_modules'), {
        recursive: true
    });
} catch(e) {
    console.error(e);
}

try {
    const file = path.resolve(__dirname, './node_modules/@types/asn1js');
    if (fs.existsSync(file)) {
        fs.rmdirSync(file, {
            recursive: true
        });
    }
} catch(e) {
    console.error(e);
}
