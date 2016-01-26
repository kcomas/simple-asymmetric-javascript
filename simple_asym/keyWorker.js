importScripts('../node_modules/node-forge/js/forge.bundle.js');
onmessage = function (event) {
    var data = JSON.parse(event.data);
    var keypair = forge.rsa.generateKeyPair({ bits: data.bits, e: 0x10001 });
    var obj = {};
    obj.public_key = forge.pki.publicKeyToPem(keypair.publicKey);
    if (data.passphrase) {
        obj.private_key = forge.pki.encryptRsaPrivateKey(keypair.privateKey, data.passphrase);
    }
    else {
        obj.private_key = forge.pki.privateKeyToPem(keypair.privateKey);
    }
    postMessage(JSON.stringify(obj));
};
