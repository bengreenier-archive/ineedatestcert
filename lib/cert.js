var merge = require('merge');
var forge = require('node-forge');
var uuid = require('uuid');
var promise = require('promise');
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
    if (this._wasCrunched) {
        return cb(this);
    }
    
    // we use this in the promise chain below
    var self = this;
    
    // construct a promise chain of all the operations needed
    // to crunch the dat for a cert
    var prom = makeKeyPair(self.opts.b).then(function (keys) {
        self.keys = keys;
        return keys;
    }).then(function makeCertInline (keys) {
        return makeCert(keys, self.opts.name, self.opts.org).then(function (cert) {
            self.cert = cert;
            return cert;
        });
    }).then(function signCertInline (cert) {
        return signCert(cert, self.keys);
    })
    .then(parallel([
        function makeRawInline(cert) {
            return makeRaw(cert, self.opts.type, self.keys, self.opts.password).then(function(raw) {
                self._raw = raw;
                return raw;
            });
        },
        function makeRawPublicInline(cert) {
            return makeRawPublic(cert).then(function (rawPub) {
                self._rawPublic = rawPub;
                return rawPub;
            });
        }]))
    .then(function makeBase64Inline (results) {
        return makeBase64(results[0]).then(function (b64) {
            self._base64 = b64;
            return b64;
        });
    })
    .then(function setCrunchedFlag () {
          self._wasCrunched = true;
          
          // and finally we want our promise to resolve to this instance
          return self;
    });
    
    if (typeof(cb) === "function") {
        prom.then(function(ok) {
            debug("calling cb");
            cb(null, ok);
        }, function (bad) {
            debug("calling cb with error");
            cb(bad);
        });
    } else {
        return prom;
    }
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

// internal only helper functions

// promise helpers

function parallel(operations) {
    return function (input) {
        var proms = [];
        for (var i = 0 ; i < operations.length ; i++) {
            proms.push(operations[i](input));
        }
        return Promise.all(proms);
    };
}

// forge helpers

function makeRaw(cert, type, keys, password) {
    return new Promise(function (res, rej) {
        // if pkcs
        var raw = null;
        if (type === "pkcs") {
            var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
                keys.privateKey, [cert], password);
                //{generateLocalKeyId: true, friendlyName: config.c}
            var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
            raw = newPkcs12Der;
        } else if (type === "pem") {
            if (!password || password === "") {
                raw = forge.pki.privateKeyToPem(keys.privateKey);
            } else {
                raw = forge.pki.encryptRsaPrivateKey(keys.privateKey, password);
            }           
            raw = raw + "\n" + forge.pki.certificateToPem(cert);
        }
        
        if (raw) {
            res(raw);
        } else {
            rej(new Error("unrecognized type: "+type));
        }
    })
}

function makeRawPublic(cert) {
    return new Promise(function (res) {
        var pub = forge.pki.certificateToPem(cert);
        res(pub);
    });
}

function makeBase64(rawData) {
    return new Promise(function (res) {
        debug("base64 encoding...");
        var base64 = forge.util.encode64(rawData);
        debug("base64 encoded.");
        res(base64);
    });
}

function makeKeyPair(keysize) {
    return new Promise(function (res) {
        debug("generating keypair....");
        var keys = forge.pki.rsa.generateKeyPair(keysize);
        debug("keypair generated.");
        res(keys);
    });
}

function makeCert(keys, name, org) {
    return new Promise(function (res) {
        var cert = forge.pki.createCertificate();
    
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

        var attrs = [{
            name: 'commonName',
            value: name
        }, {
            name: 'organizationName',
            value: org
        }, {
            shortName: 'OU',
            value: org
        }];
        
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        
        cert.setExtensions([{
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
                value: 'http://ineedatestcert.com/'+name
            }]
        }, {
            name: 'subjectKeyIdentifier'
        }]);
        
        res(cert);
    });
}

function signCert(cert, keys) {
    return new Promise(function (res) {
        debug("cert ready, signing...");
        cert.sign(keys.privateKey, forge.md.sha256.create());
        debug("cert signed.");
        res(cert);
    });
}