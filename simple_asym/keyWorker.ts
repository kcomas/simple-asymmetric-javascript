/**
 * The node forge global varable
 * @type {forge}
 */
declare var forge: any;

declare function postMessage(data:any): any;

/**
 * The object for returning the keys and passpharse
 * @property {string} private_key - as a pem string
 * @property {string} public_key - as a pem string
 * @property {string} passphrase - the password for the private key
 */
interface keyObj {
    private_key?:string,
    public_key?:string,
    passphrase?:string
}

onmessage = (event) =>{
    var keypair = forge.rsa.generateKeyPair({bits: event.data.bits, e: 0x10001});
    var obj:keyObj = {};
    obj.public_key = forge.pki.publicKeyToPem(keypair.publicKey);
    if(event.data.passphrase){
        obj.private_key = forge.pki.encryptRsaPrivateKey(keypair.privateKey,event.data.passphrase);
    } else {
        obj.private_key = forge.pki.privateKeyToPem(keypair.privateKey);
    }
    postMessage(JSON.stringify(obj));
};
