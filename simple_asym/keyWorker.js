onmessage = function (event) {
    var keypair = forge.rsa.generateKeyPair({ bits: event.data.bits, e: 0x10001 });
    var obj = {};
    obj.public_key = forge.pki.publicKeyToPem(keypair.publicKey);
    if (event.data.passphrase) {
        obj.private_key = forge.pki.encryptRsaPrivateKey(keypair.privateKey, event.data.passphrase);
    }
    else {
        obj.private_key = forge.pki.privateKeyToPem(keypair.privateKey);
    }
    postMessage(JSON.stringify(obj));
};
