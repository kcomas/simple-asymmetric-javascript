/**
 * The node forge global varable
 * @type {forge}
 */
declare var forge: any;

importScripts('../node_modules/node-forge/js/forge.bundle.js');

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
    var data = JSON.parse(event.data);
    var keypair = forge.rsa.generateKeyPair({bits: data.bits, e: 0x10001});
    var obj:keyObj = {};
    obj.public_key = forge.pki.publicKeyToPem(keypair.publicKey);
    if(data.passphrase){
        obj.private_key = forge.pki.encryptRsaPrivateKey(keypair.privateKey,data.passphrase);
    } else {
        obj.private_key = forge.pki.privateKeyToPem(keypair.privateKey);
    }
    postMessage(JSON.stringify(obj));
};
