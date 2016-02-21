var merge = require('merge');
var forge = require('node-forge');
var uuid = require('uuid');
var debug = require('debug')('ineedatestcert.cert');

/**
 * a certificate
 */
function Cert(opts) {
    this.opts = merge({
        type: "pkcs",
        name: uuid.v4()+".ineedatestcert.com",
        org: "Test Cert",
        b: 2048,
        password: ''
    }, opts);
    
    if (this.opts.type !== "pkcs" && this.opts.type !== "pem") {
        throw new Error("type needs to be pkcs or pem");
    }
    if (typeof(this.opts.b) !== "number") {
        throw new Error("b needs to be a number");
    }
    if (typeof(this.opts.name) !== "string") {
        throw new Error("name needs to be a string");
    }
    if (typeof(this.opts.org) !== "string") {
        throw new Error("org needs to be a string");
    }
    if (typeof(this.opts.password) !== "string") {
        throw new Error("password should be a string (can be empty)");
    }
    this._wasCrunched = false;
}

/**
 * I do the actual work of creating the cert
 * 
 * @param Function cb called when crunching is complete
 */
Cert.prototype.crunch = function (cb) {
    if (typeof(cb) === "undefined") {
        cb = function(){};
    }
    
    if (this._wasCrunched) {
        return cb(this);
    }
    debug("generating keypair....");
    this.keys = forge.pki.rsa.generateKeyPair(this.opts.b);
    debug("keypair generated.");
    
    this.cert = forge.pki.createCertificate();
    
    this.cert.publicKey = this.keys.publicKey;
    this.cert.serialNumber = '01';
    this.cert.validity.notBefore = new Date();
    this.cert.validity.notAfter = new Date();
    this.cert.validity.notAfter.setFullYear(this.cert.validity.notBefore.getFullYear() + 1);

    var attrs = [{
            name: 'commonName',
            value: this.opts.name
        }, {
            name: 'organizationName',
            value: this.opts.org
        }, {
            shortName: 'OU',
            value: this.opts.org
        }];
        this.cert.setSubject(attrs);
        this.cert.setIssuer(attrs);
        this.cert.setExtensions([{
            name: 'basicConstraints',
            cA: true
        }, {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        }, {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true
        }, {
            name: 'nsCertType',
            client: true,
            server: true,
            email: true,
            objsign: true,
            sslCA: true,
            emailCA: true,
            objCA: true
        }, {
            name: 'subjectAltName',
            altNames: [{
                type: 6, // URI
                value: 'http://ineedatestcert.com/'+this.opts.name
            }]
        }, {
            name: 'subjectKeyIdentifier'
    }]);

    debug("cert ready, signing...");
    this.cert.sign(this.keys.privateKey, forge.md.sha256.create());
    debug("cert signed.");
    
    // if pkcs
    if (this.opts.type === "pkcs") {
        var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
            this.keys.privateKey, [this.cert], this.opts.password);
            //{generateLocalKeyId: true, friendlyName: config.c}
        var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
        this._raw = newPkcs12Der;
    } else if (this.opts.type === "pem") {
        // TODO does this look okay? might need a \n
        this._raw = forge.pki.privateKeyToPem(this.keys.privateKey) +
            forge.pki.certificateToPem(this.cert);
    }
    
    // TODO: does this have private bits in it?
    this._rawPublic = forge.pki.certificateToPem(this.cert);
    
    debug("base64 encoding...");
    this._base64 = forge.util.encode64(this._raw);
    debug("base64 encoded.");
    
    this._wasCrunched = true;
    return cb(this);
}

/**
 * Get the base64 representation - must call crunch() first
 */
Cert.prototype.getBase64 = function () {
    return this._base64;
}

/**
 * Get the raw representation - must call crunch() first
 */
Cert.prototype.getRaw = function () {
    return this._raw;
}

/**
 * Get the raw representation of public only bits - must call crunch() first
 */
Cert.prototype.getRawPublicOnly = function () {
    return this._rawPublic;
}

// export our class - ctor
module.exports = Cert;