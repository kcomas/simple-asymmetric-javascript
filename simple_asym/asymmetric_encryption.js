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
        /**
         * Get the public key as a pem string
         * @return {string} the public key as a pem string
         */
        Object.defineProperty(this, 'public_key', {
            get: function () {
                return forge.pki.publicKeyToPem(this._public_key);
            }
        });
    }
    /**
     * Generate a fernet key
     * @return {string} the base64 encoded key
     */
    AsymCrypt.prototype._generate_key = function () {
        var bytes = forge.random.getBytesSync(32);
        return forge.util.encode64(bytes);
    };
    /**
     * Generate a random passpharse
     * @param {number} N - the size of the passphrase defaults to 255
     */
    AsymCrypt.prototype._generate_passphrase = function (N) {
        if (N === void 0) { N = 255; }
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (var i = 0; i < N; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    };
    /**
     * Generate public and private keys in a web worker
     * @param {string} passphrase - the passpharse to encrypt the private key
     * @param {number} bits - bit size of the private key defaults to 2048
     * @param {function} callback(keys:object)} - when the keys return the key object in it
     */
    AsymCrypt.prototype.make_rsa_keys = function (passphrase, bits, callback) {
        var _this = this;
        if (bits === void 0) { bits = 2048; }
        var worker = new Worker('../simple_asym/keyWorker.js');
        worker.postMessage(JSON.stringify({ passphrase: passphrase, bits: bits }));
        worker.onmessage = function (event) {
            var data = JSON.parse(event.data);
            _this.set_private_key(data.private_key, passphrase);
            _this.set_public_key(data.public_key);
            if (!callback) {
                return passphrase(event.data);
            }
            else {
                return callback(event.data);
            }
        };
    };
    /**
     * Wrapper for making the public and private keys with an auto generated passphrase
     * @param {number} bits - the number of bits to use
     * @param {function(keys:object)} callback - callback with the key data
     */
    AsymCrypt.prototype.make_rsa_keys_with_passphrase = function (bits, callback) {
        if (bits === void 0) { bits = 2048; }
        var passphrase = this._generate_passphrase();
        var obj = this.make_rsa_keys(passphrase, bits, function (keys) {
            obj.passphrase = passphrase;
            return callback(obj);
        });
    };
    /**
     * Encrypt plain text
     * @param {string} text - the text to encrypt
     * @param {boolean} use_base64 - encode the encrypted text as base64
     */
    AsymCrypt.prototype.rsa_encrypt = function (text, use_base64) {
        if (!this._public_key) {
            throw new Error("Missing Public Key");
            return;
        }
        var encrypted = this._public_key.encrypt(text, 'RSA-OAEP', {
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
        if (!this._private_key) {
            throw new Error("Missing Private Key");
            return;
        }
        return this._private_key.decrypt(ciphertext, 'RSA-OAEP', {
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
        this._aes_key = aes_key;
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
     * Generate the aes secret
     * @return {string} the aes key secret as base64
     */
    AsymCrypt.prototype.make_aes_key = function () {
        var key = key = this._generate_key();
        this.set_aes_key(key);
        return key;
    };
    /**
     * Get encrypted aes key from a public key
     * @param {string} public_key - the public key as a pem string
     * @param {boolean} use_base64 - encode the aes key as base64
     * @return {string} the encrypted aes key
     */
    AsymCrypt.prototype.get_encrypted_aes_key = function (public_key, use_base64) {
        var public_asym = new AsymCrypt(null, null, public_key);
        var encrypted_key = public_asym.rsa_encrypt(this._aes_key);
        if (use_base64) {
            encrypted_key = forge.util.encode64(encrypted_key);
        }
        return encrypted_key;
    };
    /**
     * Set the private key
     * @param {string|object} private_key - the private key
     * @param {string} passphrase - the passphrase if the private key is encrypted
     */
    AsymCrypt.prototype.set_private_key = function (private_key, passphrase) {
        if (passphrase) {
            this._private_key = forge.pki.decryptRsaPrivateKey(private_key, passphrase);
        }
        else if (typeof private_key !== 'string') {
            this._private_key = private_key;
        }
        else {
            this._private_key = forge.pki.privateKeyFromPem(private_key);
        }
    };
    /**
     * Set the public key
     * @param {string|object} public_key - the public key
     */
    AsymCrypt.prototype.set_public_key = function (public_key) {
        if (typeof public_key !== 'string') {
            this._public_key = public_key;
        }
        else {
            this._public_key = forge.pki.publicKeyFromPem(public_key);
        }
    };
    /**
     * Encrypt text using aes encryption
     * @param {string} text - the text to encrypt
     * @return {string} the encrypted string
     */
    AsymCrypt.prototype.encrypt = function (text) {
        var token = new fernet.Token({
            secret: new fernet.Secret(this._aes_key)
        });
        return token.encode(text);
    };
    /**
     * Decrypt text using aes encryption
     * @param {string} text - the text to decrypt
     * @return {string} the decrypted text
     */
    AsymCrypt.prototype.decrypt = function (text) {
        var token = new fernet.Token({
            secret: new fernet.Secret(this._aes_key),
            token: text,
            ttl: 0
        });
        return token.decode();
    };
    return AsymCrypt;
})();
