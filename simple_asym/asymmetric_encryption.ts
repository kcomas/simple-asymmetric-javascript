
/**
 * The node forge global varable
 * @type {forge}
 */
declare var forge: any;

/**
 * The fernet global varable
 * @type {fernet}
 */
declare var fernet: any;

/**
 * Class for encrypting and decrypting fernet strings
 */
class AsymCrypt {

    /**
     * The public key
     * @type {pki}
     */
    private public_key: any;

    /**
     * The private key
     * @type {pki}
     */
    private private_key: any;

    /**
     * The aes key
     * @type {string}
     */
    private aes_key: string;

    /**
     * Int the class
     * @param {string} aes_key - the aes key
     * @param {string} private_key - the private key as a pem string
     * @param {string} public_key - the public key as a pem string
     */
    constructor(aes_key?:string, private_key?:string, public_key?:string){
        if(aes_key){
            this.set_aes_key(aes_key);
        }
        if(private_key){
            this.set_private_key(private_key);
        }
        if(public_key){
            this.set_public_key(public_key);
        }
    }

    /**
     * Generate public and private keys
     * @param {string} passphrase - the passpharse to encrypt the private key
     * @param {number} bits - bit size of the private key defaults to 4096
     * @return {object} the public and private key as pem format in an object
     */
    make_rsa_keys(passphrase:string, bits:number=4096): any {
        var keypair = forge.rsa.generateKeyPair({bits: bits, e: 0x10001});
    }

    /**
     * Encrypt plain text
     * @param {string} text - the text to encrypt
     * @param {boolean} use_base64 - encode the encrypted text as base64
     */
    rsa_encrypt(text:string, use_base64:boolean): string {
        if(!this.public_key){
            throw new Error("Missing Public Key");
            return;
        }
        var encrypted = this.public_key.encrypt(text, 'RSA-OAEP', {
            mgf1: {
                md: forge.md.sha1.create()
            }
        });
        if(use_base64){
            encrypted = forge.util.encode64(encrypted); 
        }
        return encrypted;
    }

    /**
     * Decrypt rsa text
     * @param {string} ciphertext - the encrypted text
     * @param {boolean} use_base64 - if the text is base64 encoded
     */
    rsa_decrypt(ciphertext:string, use_base64?:boolean): string {
        if(use_base64){
            ciphertext = forge.util.decode64(ciphertext);
        }
        if(!this.private_key){
            throw new Error("Missing Private Key");
            return;
        }
        return this.private_key.decrypt(ciphertext, 'RSA-OAEP',{
            mgf1: {
                md: forge.md.sha1.create()
            }
        });

    }
    
    /**
     * Set the aes key
     * @param {string} aes_key - the new aes key
     */
    set_aes_key(aes_key:string): void {
        this.aes_key = aes_key;
    }

    /**
     * Set the aes_key from an an encrypted base64 string
     * @param {string} aes_key - the encrypted aes_key
     * @param {boolean} use_base64 - if the aes key is base64 encoded
     */
    set_aes_key_from_encrypted(aes_key:string, use_base64?:boolean): void {
        if(use_base64){
            aes_key = forge.util.decode64(aes_key);
        }
        this.set_aes_key(rsa_decrypt(aes_key));
    }

    /**
     * Set the private key
     * @param {string|object} private_key - the private key
     * @param {string} passphrase - the passphrase if the private key is encrypted
     */
    set_private_key(private_key:any, passphrase?:string): void {
        if(passphrase){
            this.private_key = forge.pki.decryptRsaPrivateKey(private_key,passphrase);
        } else if(typeof private_key !== 'string'){
            this.private_key = private_key;
        } else {
            this.private_key = forge.pki.privateKeyFromPem(private_key);
        }
    }

    /**
     * Set the public key
     * @param {string|object} public_key - the public key
     */
    set_public_key(public_key:any): void {
        if(typeof public_key !== 'string'){
            this.public_key = public_key;
        } else {
            this.public_key = forge.pki.publicKeyFromPem(public_key);
        }
    }

}

export default AsymCrypt;
