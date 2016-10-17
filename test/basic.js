var Cert = require('../lib/cert');
var expect = require('expect');
var b64decode = require('node-forge').util.decode64;

/**
 * You can debug the internals that are tested here
 * by setting DEBUG=ineedatestcert.cert
 */
describe("ineedatestcert.cert", function () {
    it("should throw on bad args", function () {
        expect(function (opts) {
            new Cert({
                type:"cat"
            });
        }).toThrow(/pkcs or pem/);
        
        expect(function (opts) {
            new Cert({
                type:1
            });
        }).toThrow(/pkcs or pem/);
        
        expect(function (opts) {
            new Cert({
                b:"cat"
            });
        }).toThrow(/b/);
        
        expect(function (opts) {
            new Cert({
                name:1
            });
        }).toThrow(/name/);
        
        expect(function (opts) {
            new Cert({
                org:1
            });
        }).toThrow(/org/);
        
        expect(function (opts) {
            new Cert({
                password:1
            });
        }).toThrow(/password/);
    });
    
    it("should pass itself to crunch cb", function (done) {
        this.timeout(1000*60);
        var cert = new Cert({
            b: 1024 // we use a smaller key size for tests
        });
        cert.crunch(function (err, self) {
            expect(err).toNotExist();
            expect(self).toBe(cert);
            done();
        });
    });
    
    it("should pass itself to crunch promise", function (done) {
        this.timeout(1000*60);
        var cert = new Cert({
            b: 1024 // we use a smaller key size for tests
        });
        cert.crunch().then(function (self) {
            expect(self).toBe(cert);
            done();
        });
    });
    
    it("should crunch successfully, given 2 minute timeout", function (done){
        this.timeout(1000*60*2);
        new Cert({}).crunch(function (err) {
            expect(err).toNotExist();
            done();
        });
    });
    
    it("should expose pem", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pem"
        }).crunch(function (err, cert) {
            expect(err).toNotExist();
            
            var pemText = cert.getRaw();
            expect(pemText).toMatch(/BEGIN RSA PRIVATE KEY/);
            expect(pemText).toMatch(/END RSA PRIVATE KEY/);
            expect(pemText).toMatch(/BEGIN CERTIFICATE/);
            expect(pemText).toMatch(/END CERTIFICATE/);
            done();
        });
    });
    
    it("should expose pkcs binary", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pkcs"
        }).crunch(function (err, cert) {
            expect(err).toNotExist();
            
            var pkcsBinary = cert.getRaw();
            // TODO: write a good isBinary() test
            expect(pkcsBinary).toExist();
            
            done();
        });
    });
    
    it("should expose pem public data", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pem"
        }).crunch(function (err, cert) {
            expect(err).toNotExist();
            
            var pemText = cert.getRawPublicOnly();
            expect(pemText).toMatch(/BEGIN CERTIFICATE/);
            expect(pemText).toMatch(/END CERTIFICATE/);
            done();
        });
    });
    
    it("should expose pkcs public data", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pkcs"
        }).crunch(function (err, cert) {
            expect(err).toNotExist();
            
            var pemText = cert.getRawPublicOnly();
            expect(pemText).toMatch(/BEGIN CERTIFICATE/);
            expect(pemText).toMatch(/END CERTIFICATE/);
            done();
        });
    });
    
    it("should expose pem as base64", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pem"
        }).crunch(function (err, cert) {
            expect(err).toNotExist();
            
            var b66Text = cert.getBase64();
            expect(function () {
                b64decode(b66Text);
            }).toNotThrow();
            done();
        });
    });
    
    it("should expose pkcs as base64", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pkcs"
        }).crunch(function (err, cert) {
            expect(err).toNotExist();
            
            var b66Text = cert.getBase64();
            expect(function () {
                b64decode(b66Text);
            }).toNotThrow();
            done();
        });
    });
});