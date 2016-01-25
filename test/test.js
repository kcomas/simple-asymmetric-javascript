
describe("Bob and Alice example",function(){
    it("Should be able to share messages",function(){
        var bob = new AsymCrypt(); 
        var alice = new AsymCrypt();
        bob.make_rsa_keys();
        alice.make_rsa_keys();
    });
});
