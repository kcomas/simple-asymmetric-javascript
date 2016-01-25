/**
 * Class for encrypting and decrypting fernet strings
 */
var AsymCrypt = (function () {
    /**
     * Int the class
     * @param {string} aes_key - the aes key
     * @param {string} private_key - the private key as a pem string
     * @param {string} public_key - the public key as a pem string
     */
    function AsymCrypt(aes_key, private_key, public_key) {
        if (aes_key) {
            this.set_aes_key(aes_key);
        }
        if (private_key) {
            this.set_private_key(private_key);
        }
        if (public_key) {
            this.set_public_key(public_key);
        }
    }
    /**
     * Generate public and private keys
     * @param {string} passphrase - the passpharse to encrypt the private key
     * @param {number} bits - bit size of the private key defaults to 4096
     * @return {object} the public and private key as pem format in an object
     */
    AsymCrypt.prototype.make_rsa_keys = function (passphrase, bits) {
        if (bits === void 0) { bits = 4096; }
        var keypair = forge.rsa.generateKeyPair({ bits: bits, e: 0x10001 });
    };
    /**
     * Encrypt plain text
     * @param {string} text - the text to encrypt
     * @param {boolean} use_base64 - encode the encrypted text as base64
     */
    AsymCrypt.prototype.rsa_encrypt = function (text, use_base64) {
        if (!this.public_key) {
            throw new Error("Missing Public Key");
            return;
        }
        var encrypted = this.public_key.encrypt(text, 'RSA-OAEP', {
            mgf1: {
                md: forge.md.sha1.create()
            }
        });
        if (use_base64) {
            encrypted = forge.util.encode64(encrypted);
        }
        return encrypted;
    };
    /**
     * Decrypt rsa text
     * @param {string} ciphertext - the encrypted text
     * @param {boolean} use_base64 - if the text is base64 encoded
     */
    AsymCrypt.prototype.rsa_decrypt = function (ciphertext, use_base64) {
        if (use_base64) {
            ciphertext = forge.util.decode64(ciphertext);
        }
        if (!this.private_key) {
            throw new Error("Missing Private Key");
            return;
        }
        return this.private_key.decrypt(ciphertext, 'RSA-OAEP', {
            mgf1: {
                md: forge.md.sha1.create()
            }
        });
    };
    /**
     * Set the aes key
     * @param {string} aes_key - the new aes key
     */
    AsymCrypt.prototype.set_aes_key = function (aes_key) {
        this.aes_key = aes_key;
    };
    /**
     * Set the aes_key from an an encrypted base64 string
     * @param {string} aes_key - the encrypted aes_key
     * @param {boolean} use_base64 - if the aes key is base64 encoded
     */
    AsymCrypt.prototype.set_aes_key_from_encrypted = function (aes_key, use_base64) {
        if (use_base64) {
            aes_key = forge.util.decode64(aes_key);
        }
        this.set_aes_key(this.rsa_decrypt(aes_key));
    };
    /**
     * Set the private key
     * @param {string|object} private_key - the private key
     * @param {string} passphrase - the passphrase if the private key is encrypted
     */
    AsymCrypt.prototype.set_private_key = function (private_key, passphrase) {
        if (passphrase) {
            this.private_key = forge.pki.decryptRsaPrivateKey(private_key, passphrase);
        }
        else if (typeof private_key !== 'string') {
            this.private_key = private_key;
        }
        else {
            this.private_key = forge.pki.privateKeyFromPem(private_key);
        }
    };
    /**
     * Set the public key
     * @param {string|object} public_key - the public key
     */
    AsymCrypt.prototype.set_public_key = function (public_key) {
        if (typeof public_key !== 'string') {
            this.public_key = public_key;
        }
        else {
            this.public_key = forge.pki.publicKeyFromPem(public_key);
        }
    };
    return AsymCrypt;
})();
