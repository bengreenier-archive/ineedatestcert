ineedatestcert
==============

[![Build Status](https://travis-ci.org/bengreenier/ineedatestcert.svg?branch=master)](https://travis-ci.org/bengreenier/ineedatestcert)

cli for generating certificates

# How

First, `npm install -g ineedatestcert` then:

> Note: The examples below use `inatc` as the command name, but you can also
fully spell it out, if you wish (ie: `ineedatestcert`)

```
$ inatc
Options:
  -h, --help      Show help                                            [boolean]
  -o, --out       specify a file to output to                    [default: null]
  -b              specify key size                               [default: 2048]
  -c, --name      specify common name     [default: "<uuid>.ineedatestcert.com"]
  -p, --password  password to use for pkcs                         [default: ""]
  -t, --type      type of output - pem or pkcs                 [default: "pkcs"]
  -u, --org       organization to use                     [default: "Test Cert"]
  -a, --ca        specify file to output ca bundle to            [default: null]

Made with <3 by @bengreenier
```

# Why?

Generating certificates in different formats on different oses is hard.
At the very least you need to remember a bunch of openssl flags and have
openssl installed everywhere. This is easier, pure js, and works everywhere.

# API

You can use `ineedatestcert` as a module, too. Just `npm install ineedatestcert` then:

```
var TestCert = require('ineedatestcert');
var myCert = new TestCert({
        type: "pkcs",
        password: "",
        name: "<uuid>.innedatestcert.com",
        org: "Test Cert",
        b: 2048
    }).crunch(function (err, self) {
        //assert.equal(err, null);
        //assert.equal(self, myCert);
        var raw = myCert.getRaw();
        var publicRaw = myCert.getRawPublicOnly();
        var base64 = myCert.getBase64();
    });
```

## Constructor

> Note: The constructor is lightweight - the certificate creation calculations
occur in `crunch()`

exposed by `require('ineedatestcert')` - used to create test cert instances.

## Crunch

> Note: crunch optionally takes a callback that gets passed any error instance,
and the instance of the test cert. It is called once all the calculations complete
(and the cert is therefore made). If it isn't passed, a promise is returned.

member function - used to actually do the maths to create the test cert data.

## GetRaw

> Note: When called with a `pem` cert, this is a string. When called with `pkcs`
this is a string of binary data. When writing `pkcs` to disk you should specify
`encoding: "binary"`

member function - returns the raw data of the test cert.

## GetRawPublicOnly

> Note: This is a `pem` style string.

member function - returns the raw data of the public bits of the test cert.

## GetBase64

member function - returns a base64 encoded representation of `GetRaw()`

# License

MIT