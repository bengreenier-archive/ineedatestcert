#!/usr/bin/env node

var Cert = require('./lib/cert');
var fs = require('fs');
var yargs = require('yargs');
var moment = require('moment');
var debug = require('debug')('ineedatestcert.cli');

/**
 * You can debug the cli by setting
 * DEBUG=ineedatestcert.cli
 * and if you also want to debug the internals
 * DEBUG=ineedatestcert.*
 */
var config = yargs
    .help('h')
    .alias('h', 'help')
    .epilog('Made with <3 by @bengreenier')
    .describe('o', 'specify a file to output to')
    .alias('o','out')
    .describe('b', 'specify key size')
    .describe('c', 'specify common name')
    .alias('c', 'name')
    .describe('p', 'password to use for pkcs')
    .alias('p', 'password')
    .describe('t', 'type of output - pem or pkcs')
    .alias('t','type')
    .describe('u', 'organization to use')
    .alias('u', 'org')
    .describe('a', 'specify file to output ca bundle to')
    .alias('a', 'ca')
    .describe('alt', 'specify alternative dns names')
    .describe('na', 'not after date')
    .default({
        na: moment().add(1, 'year').toISOString(),
        alt: [],
        a: null, // filpath to write ca bundle to - if null, not written
        b: 2048, // any more get's real slow
        c: "<uuid>.ineedatestcert.com", // generate a unique subdomain
        u: "Test Cert", // the ou/organization name (shared)
        p: "", // only used with pkcs==true
        t: "pkcs", // or pem
        o: null // filepath to write to - if null, writes to console
    }).argv;

// you need to use a legit t argument...
if (config.t !== "pkcs" && config.t !== "pem") {
    debug("unknown argument t: "+config.t);
    yargs.showHelp();
    process.exit(-1);
}

// if <uuid> is still in c, we need to replace it with an actual uuid
// but Cert does that for us
if (config.c.indexOf("<uuid>") === 0) {
    delete config.c;
    delete config.name; // fix the alias too
}

// if using -p <password> and -t <pem> warn
if (config.p && config.t === "pem") {
    console.warn("[WARN] using -p and -t pem together isn't possible. you probably mean -t pkcs\n");
}

debug("using configuration: "+JSON.stringify(config));

var cert = new Cert(config);

cert.crunch(function calculated(err) {
    if (err) {
        return console.error(err);
    }
    if (config.a) {
        fs.writeFileSync(config.a, cert.getRawPublicOnly());
        if (config.o) {
            console.log("wrote "+config.a);
        }
        debug("wrote ca bundle to "+config.a);
    }
    if (config.o) {
        fs.writeFileSync(config.o, cert.getRaw(), {encoding: "binary"});
        console.log("wrote "+config.o);
        debug("wrote raw to "+config.o);
    } else {
        console.log(cert.getBase64());
    }
    debug("complete.");
});
