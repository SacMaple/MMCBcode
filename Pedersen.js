'use strict';

//ec library
var EC = require('elliptic').ec;

//for pedersen usage
var ec = new EC('secp256k1');

var crypto = require('crypto');

var BN = require('bn.js');


/*for pedersen commitment */
class Pedersen {
    
    /**
    * commit to a Value X
    * 
    * @param {*} H - second base point
    * @param {*} r - blind factor
    * @param {*} x - value
    */
    static commitTo(H, r, x) {
        return ec.g.mul(r).add(H.mul(x));
    }

    // sum two commitments
    static add(Cx, Cy) {
        return Cx.add(Cy);
    }

    // subtract two commitments
    static sub(Cx, Cy) {
        return Cx.add(Cy.neg());
    }

    // add two known values with blinding factors
    //   and compute the committed value
    //   add rX + rY (blinding factor private keys)
    //   add vX + vY (hidden values)
    static addPrivately(H, rX, rY, vX, vY) {
        // umod to wrap around if negative
        var rZ = rX.add(rY).umod(ec.n);
        return ec.g.mul(rZ).add(H.mul(vX + vY));
    }

    // subtract two known values with blinding factors
    //   and compute the committed value
    //   add rX - rY (blinding factor private keys)
    //   add vX - vY (hidden values)
    static subPrivately(H, rX, rY, vX, vY) {
        // umod to wrap around if negative
        var rZ = rX.sub(rY).umod(ec.n);
        return ec.g.mul(rZ).add(H.mul(vX - vY));
    }

    /**
     * Verifies that the commitment given is the same
     * 
     * @param {*} H - secondary point
     * @param {*} C - commitment
     * @param {*} r - blinding factor private key used to create the commitment
     * @param {*} v - original value committed to
     */
    static verify(H, C, r, v) {
        return ec.g.mul(r).add(H.mul(v)).eq(C);
    }

    /**
     * generate a random number
     */
    static generateRandom() {
        var random;
        do {
            random = new BN((crypto.randomBytes(32).toString('hex')), 'hex');
            //random = HN.toBN(HN.fromBuffer(crypto.randomBytes(32));
        } while (random.gte(ec.n)); // make sure it's in the safe range
        return random;
    }

    /*
    generate a random point
     */
    static generateH() {
        return ec.g.mul(generateRandom());
    }
}

module.exports = Pedersen;