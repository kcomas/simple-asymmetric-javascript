
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
    private _public_key: any;

    /**
     * The private key
     * @type {pki}
     */
    private _private_key: any;

    /**
     * The aes key
     * @type {string}
     */
    private _aes_key: string;

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

        /**
         * Get the public key as a pem string
         * @return {string} the public key as a pem string
         */
        Object.defineProperty(this, 'public_key', {
            get : function(){
                return forge.pki.publicKeyToPem(this._public_key);
            }
        });
    }

    /**
     * Generate a fernet key
     * @return {string} the base64 encoded key
     */
    private _generate_key(): string {
        var bytes = forge.random.getBytesSync(32);
        return forge.util.encode64(bytes);
    }

    /**
     * Generate public and private keys
     * @param {string} passphrase - the passpharse to encrypt the private key
     * @param {number} bits - bit size of the private key defaults to 2048
     * @return {object} the public and private key as pem format in an object
     */
    make_rsa_keys(passphrase:string, bits:number=2048): any {
        var keypair = forge.rsa.generateKeyPair({bits: bits, e: 0x10001});
        this._private_key = keypair.privateKey;
        this._public_key = keypair.publicKey;
        var obj = {
            public_key:null,
            private_key:null
        };
        obj.public_key = forge.pki.publicKeyToPem(this._public_key);
        if(passphrase){
            obj.private_key = forge.pki.encryptRsaPrivateKey(this._private_key,passphrase);
        } else {
            obj.private_key = forge.pki.privateKeyToPem(this._private_key);
        }
        return obj;
    }

    /**
     * Encrypt plain text
     * @param {string} text - the text to encrypt
     * @param {boolean} use_base64 - encode the encrypted text as base64
     */
    rsa_encrypt(text:string, use_base64?:boolean): string {
        if(!this._public_key){
            throw new Error("Missing Public Key");
            return;
        }
        var encrypted = this._public_key.encrypt(text, 'RSA-OAEP', {
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
        if(!this._private_key){
            throw new Error("Missing Private Key");
            return;
        }
        return this._private_key.decrypt(ciphertext, 'RSA-OAEP',{
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
        this._aes_key = aes_key;
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
        this.set_aes_key(this.rsa_decrypt(aes_key));
    }

    /**
     * Generate the aes secret
     * @return {string} the aes key secret as base64
     */
    make_aes_key(): string {
        var key = key = this._generate_key();
        this.set_aes_key(key);
        return key;
    }

    /**
     * Get encrypted aes key from a public key
     * @param {string} public_key - the public key as a pem string
     * @param {boolean} use_base64 - encode the aes key as base64
     * @return {string} the encrypted aes key
     */
    get_encrypted_aes_key(public_key:string, use_base64?:boolean): string {
        var public_asym = new AsymCrypt(null,null,public_key);
        var encrypted_key = public_asym.rsa_encrypt(this._aes_key);
        if(use_base64){
            encrypted_key = forge.util.encode64(encrypted_key);
        }
        return encrypted_key;
    }

    /**
     * Set the private key
     * @param {string|object} private_key - the private key
     * @param {string} passphrase - the passphrase if the private key is encrypted
     */
    set_private_key(private_key:any, passphrase?:string): void {
        if(passphrase){
            this._private_key = forge.pki.decryptRsaPrivateKey(private_key,passphrase);
        } else if(typeof private_key !== 'string'){
            this._private_key = private_key;
        } else {
            this._private_key = forge.pki.privateKeyFromPem(private_key);
        }
    }

    /**
     * Set the public key
     * @param {string|object} public_key - the public key
     */
    set_public_key(public_key:any): void {
        if(typeof public_key !== 'string'){
            this._public_key = public_key;
        } else {
            this._public_key = forge.pki.publicKeyFromPem(public_key);
        }
    }

    /**
     * Encrypt text using aes encryption
     * @param {string} text - the text to encrypt
     * @return {string} the encrypted string
     */
    encrypt(text:string): string {
        var token = new fernet.Token({
            secret: new fernet.Secret(this._aes_key),
        });
        return token.encode(text);
    }

    /**
     * Decrypt text using aes encryption
     * @param {string} text - the text to decrypt
     * @return {string} the decrypted text
     */
     decrypt(text:string): string {
        var token = new fernet.Token({
            secret: new fernet.Secret(this._aes_key),
            token: text,
            ttl: 0
        });
        return token.decode();
     }

}
