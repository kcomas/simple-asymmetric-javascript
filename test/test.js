
describe("Bob and Alice example",function(){
    it("Should be able to share messages",function(done){
        var bob = new AsymCrypt(); 
        var alice = new AsymCrypt();
        bob.make_rsa_keys(function(keys){
            alice.make_rsa_keys(function(keys){;
                bob.make_aes_key();
                var shared_encrypted_aes = bob.get_encrypted_aes_key(alice.public_key);
                alice.set_aes_key_from_encrypted(shared_encrypted_aes);
                var msg = "hello";
                var msg_ciphertext = bob.encrypt(msg);
                expect(msg_ciphertext).not.toEqual(msg);
                var decrypted_msg = alice.decrypt(msg_ciphertext);
                expect(decrypted_msg).toEqual(msg);
                done();
            });
        });
    },20000);
});
