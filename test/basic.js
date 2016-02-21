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
            new Cert(opts);
        }).withArgs({
            type:"cat"
        }).toThrow(/pkcs or pem/);
        
        expect(function (opts) {
            new Cert(opts);
        }).withArgs({
            type:1
        }).toThrow(/pkcs or pem/);
        
        expect(function (opts) {
            new Cert(opts);
        }).withArgs({
            b:"cat"
        }).toThrow(/b/);
        
        expect(function (opts) {
            new Cert(opts);
        }).withArgs({
            name:1
        }).toThrow(/name/);
        
        expect(function (opts) {
            new Cert(opts);
        }).withArgs({
            org:1
        }).toThrow(/org/);
        
        expect(function (opts) {
            new Cert(opts);
        }).withArgs({
            password:1
        }).toThrow(/password/);
    });
    
    it("should pass itself to crunch cb", function (done) {
        this.timeout(1000*60);
        var cert = new Cert({
            b: 1024 // we use a smaller key size for tests
        });
        cert.crunch(function (self) {
            expect(self).toBe(cert);
            done();
        });
    });
    
    it("should crunch successfully, given 2 minute timeout", function (done){
        this.timeout(1000*60*2);
        new Cert({}).crunch(function () {
            done();
        });
    });
    
    it("should expose pem", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pem"
        }).crunch(function (cert) {
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
        }).crunch(function (cert) {
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
        }).crunch(function (cert) {
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
        }).crunch(function (cert) {
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
        }).crunch(function (cert) {
            var b66Text = cert.getBase64();
            expect(b64decode).withArgs(b66Text).toNotThrow();
            done();
        });
    });
    
    it("should expose pkcs as base64", function (done) {
        this.timeout(1000*60);
        new Cert({
            b: 1024, // we use a smaller key size for tests
            type: "pkcs"
        }).crunch(function (cert) {
            var b66Text = cert.getBase64();
            expect(b64decode).withArgs(b66Text).toNotThrow();
            done();
        });
    });
});