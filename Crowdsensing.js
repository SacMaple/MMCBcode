/***************************************************************************************************************
***************************************************************************************************************

 This version has not been thoroughly checked.

This is the chaincode for incentive mechanism experiment written in nodejs for fabric -version 2.3 (?).
Only for testing the performance, not for commerical usage.


Deploy the fabric network.
Deploy the crowdsensing contract to fabric network.


-Note that this single contract includes many functions which are indeed the named contracts in the paper.
-The contract is for performance test only. Should be improved for real world application!
-Some basic functions (CURD) are omitted for simplicity.


references:
* Hyperledger Fabric
** Hyperledger Fabric github: https://github.com/hyperledger/fabric
** Hyperledger Fabric document: https://hyperledger-fabric.readthedocs.io/en/latest/

* libraries
** js-nacl library: https://github.com/tonyg/js-nacl
** tweetnacl library: https://github.com/dchest/tweetnacl-js
** nodejs-aes 256 library: https://github.com/jaysvoboda/nodejs-aes256
** elliptic library: https://github.com/indutny/elliptic


v0 function of intilization
v1 function of register
v2 function of task post
v3 function of bidding
v4 function of revealbid
v5 function of incentive mechanism
v6 function of data submission
v7 function of payment
v8 debugging
v9 adding remarks


signature is using ed25519

* Add: pedersen is using secp256k1


 Copyright. 2022


***************************************************************************************************************
***************************************************************************************************************
***************************************************************************************************************
***************************************************************************************************************
***************************************************************************************************************/

/**  library reliance  **/

'use strict';

//fabric api
const { Contract } = require('fabric-contract-api');

//library of nacl
const nacl = require('tweetnacl');

//library of file written
const fs = require('fs');

//library of aes256
const aes256 = require('nodejs-aes256');

//ec library
const EC = require('elliptic').ec;

//for pedersen usage
const ec = new EC('secp256k1');

const crypto = require('crypto');

const BN = require('bn.js');

//for filewritten
const readFileLines = filename =>
  fs
    .readFileSync(filename)
    .toString('UTF8')
    .split('\n');


/***************************************************************************************************************
***************************************************************************************************************/

/**  file reliance  **/

//reliance: base64helper
const Base64Helper = require('./Helper');

//reliance: pedersen commitment
const Pedersen = require('./Pedersen');

//reliance: toUint8Arr
const StringTrans = require('./StringTrans');


/***************************************************************************************************************
***************************************************************************************************************/

/**  defined functions  **/

/**
* Calculate function f in Incentive Mechanism 
* 
* @param {*} S - current winner set
* @param {*} user_taskset - array of workers' task sets
* @param {*} TASKNUM - number of tasks
* @param {*} hk - array of weights of tasks
*/
function Cal_f(S,user_taskset,TASKNUM,hk){
    
    //parameter lambda in default setting
    const lambda=0.8;

    //nk array
    let nk = new Array();

    for (let i = 0; i < TASKNUM; i++){
        nk[i] = 0;
    }

    //cal nk based on the winner set S
    for (let i = 1; i <= S[0]; i++){
        let this_winner = S[i];
        for (let j = 1; j <= user_taskset[this_winner][0]; j++){
            let this_task = user_taskset[this_winner][j];
            nk[this_task]++;
        }
    }

    let sum = 0;

    //sum up nk
    for (let i = 0; i < TASKNUM; i++){
        sum += hk[i] * Math.log(1 + lambda * nk[i]);
    }

    return sum;
}


/**
* Calculate fi(S) in incentive mechanism 
* 
* @param {*} i - calculated user
* @param {*} S - current winner set
* @param {*} user_taskset - array of workers' task sets
* @param {*} TASKNUM - number of tasks
* @param {*} hk - array of weights of tasks
*/
function Cal_fi_S(i, S, user_taskset, TASKNUM, hk){

    //winner set
	S[0]++;

	S[S[0]] = i;

    //f(S\cup i)
	let value_si = Cal_f(S, user_taskset, TASKNUM, hk);

	S[0]--;

    //f(S)
	let value_s = Cal_f(S, user_taskset, TASKNUM, hk);

    //f(S\cup i)-f(S)
	return value_si - value_s;
}


/**
* calculate the argmax function in incentive mechanism
* 
* @param {*} S - current winner set
* @param {*} exclude_e - excluded worker e (if exists)
* @param {*} exclude_S - excluded winner set S (if exists)
* @param {*} user_taskset - array of workers' task sets
* @param {*} user_bid - array of workers' bidding prices
* @param {*} USERNUM - number of workers
* @param {*} TASKNUM - number of tasks
* @param {*} hk - array of weights of tasks
*/
function argmax_withbid(S,exclude_e,exclude_S,user_taskset,user_bid,USERNUM,TASKNUM,hk){
	//record maxvalue
    let max_value = 0;
    //record maxe
	let max_e = 0;

    //indicate whether a user can be selected
	let f_user = new Array();

	for (let i = 0; i < USERNUM; i++){
		f_user[i] = 1;
	}

    //exclude users
	for (let i = 1; i <= exclude_S[0]; i++){
		f_user[exclude_S[i]] = 0;
	}	

    //for different situations of argmax (whether a bidder is excluded)
	if (exclude_e != 999999) {f_user[exclude_e] = 0;}

	for (let i = 0; i < USERNUM; i++){
        //excluding users
		if (!f_user[i]){
			continue;
		}

        //calculate fi(S) for users
		let this_value = Cal_fi_S(i, S, user_taskset, TASKNUM, hk) / user_bid[i];
		if (this_value > max_value){
			max_value = this_value;
			max_e = i;
		}
	}

    //return the user with max marginal value
	return max_e;
}


/**
*verify ring signature ?
* should be checked and corrected (tip)
* 
* @param {*} n - ring size (json)
* @param {*} I - key image (point in base64)
* @param {*} c1 - c_1 (bn in base64)
* @param {*} s - array of s (s_1,...,s_n) (bn in base64)
* @param {*} publickey - publickey array of ring members (point in base64)
*/
function verifyRingSignature(input_n, input_I, input_c1, input_s,input_publickey) {
    
    //translations
    let n = JSON.parse(input_n); // n: number

    let I = ec.curve.decodePoint( Base64Helper.base64ToBuf(input_I)); // I:buffer
   
    let c1 =  new BN (Base64Helper.base64ToBuf(input_c1)); // c1: value
  
    //s: array of value
    let s = new Array();
    for (let k = 1; k <= n; k++){
        s[k] = new BN (Base64Helper.base64ToBuf(input_s[k])); 
    }
 
    //publickey: array of point
    let publickey = new Array();
    for (let k = 1; k <= n; k++){
        publickey[k] = ec.curve.decodePoint( Base64Helper.base64ToBuf(input_publickey[k]));
    }

    //parameters
    let L = new Array();
    let R = new Array();
    let c = new Array();
    c[1] = c1;

    //calculation
    for (let k = 1; k <= n; k++){
        //calculate L
        L[k] = ec.g.mul(s[k]).add( publickey[k].mul( c[k]) );
        
        //publickey point->buffer
        var buf_publickey =  Buffer.from(publickey[k].encodeCompressed());

        //hash point
        var hash = ec.hash().update( buf_publickey ).digest();
        var scalar = ec.keyFromPrivate(hash).getPrivate();
        var point = ec.g.mul(scalar); //Hp(PU1)

        //calculate R
        R[k] = point.mul(s[k]).add( I.mul(c[k]) );

        //L,R point->buffer
        var buf_L =  Buffer.from(L[k].encodeCompressed());
        var buf_R =  Buffer.from(R[k].encodeCompressed());

        //combine buffer
        var combined = Buffer.concat([buf_L, buf_R], buf_L.length + buf_R.length);

        //calculate c
        c[k+1] = new BN (crypto.createHash('sha256').update(combined).digest());
        
    }

    //succeeds if c[n+1] == c[1]
    return c[n+1].eq(c[1]);
}


/***************************************************************************************************************
***************************************************************************************************************/

/**  main contract  **/

/*crowdsensing contract content begins */
class Crowdsensing extends Contract {

    /**
    * Initilization
    * (Not a must)
    * 
    */
    async InitLedger(ctx) {
        const assets = [
                    
        ];

        for (const asset of assets) {
            asset.docType = 'asset';
            await ctx.stub.putState(asset.ID, Buffer.from(JSON.stringify(asset)));
            console.info(`Asset ${asset.ID} initialized`);
        }
    }


    /**
    * register contract
    * 
    * @param {*} id - ID
    * @param {*} publickey - signer's publickey in base64
    * @param {*} signature - submitted signature in base64
    */
    async Register(ctx, id, publickey, signature) {
        //time start
        var start = Date.now();
        
        //check the duplication of ID
        const exists = await this.AssetExists(ctx, id);
        
        //ID duplication -> Error
        if (exists) {
            throw new Error(`ID duplication in Register`);
        }
        
        //translation
        let signArray = StringTrans.toUint8Arr('Register');

        //base64 to buffer
        let trans_publickey = Base64Helper.base64ToBuf(publickey);
        let trans_signature = Base64Helper.base64ToBuf(signature);

        //verify result of signature
        const verify = nacl.sign.detached.verify(signArray, trans_signature, trans_publickey);
        
        //verify fails
        if (!verify) {
            throw new Error(`Signature verification fails in Register`);
        }

        //caclulate hash
        const hash = nacl.hash(trans_publickey);

        //write information
        const asset = {
            ID: id,
            Type: 'User',
            PublicKey: publickey,
            PublicKeyHash: Base64Helper.bufToBase64(hash),
        };

        //write to ledger
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));

        //time end
        var end = Date.now();

        //runtime output
        console.log("time of Register:",(end-start).toString());

        //register succeeds
        return true;
    }
    
   
    /**
    * task post contract
    * 
    * @param {*} id - ID
    * @param {*} name - task name in string
    * @param {*} location - task location in string
    * @param {*} description - task description in string
    * @param {*} UID - requester's ID
    * @param {*} publickey - signer's publickey in base64
    * @param {*} signature - submitted signature in base64
    */
    async TaskPost(ctx, id, name, location, description, UID, publickey, signature) {
        //time start
        var start = Date.now();

        //check the duplication of ID
        const exists = await this.AssetExists(ctx, id);
        
        //ID duplication -> Error
        if (exists) {
            throw new Error(`ID duplication in TaskPost`);
        }
        
        //translation
        let signArray = StringTrans.toUint8Arr('Taskpost');

        //base64 to buffer
        let trans_publickey = Base64Helper.base64ToBuf(publickey);
        let trans_signature = Base64Helper.base64ToBuf(signature);

        //combine the information for hashing
        let hashinfo = id+ name+ location+ description;

        //verify
        const verify = nacl.sign.detached.verify(signArray,trans_signature,trans_publickey);

        //verify result of signature
        if (!verify) {
            throw new Error(`Signature verification fails in TaskPost`);
        }

        //calculate hash
        const hash = nacl.hash(StringTrans.toUint8Arr(hashinfo));

        //write information
        const asset = {
            ID: id,
            Name: name,
            Location: location,
            Description: description,
            Digest: Base64Helper.bufToBase64(hash),
            ownerUID: UID,
        };

        //write to ledger
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));

        //time end
        var end = Date.now();

        //runtime output
        console.log("time of TaskPost:",(end-start).toString());

        //task post succeeds
        return true;
    }


    /**
    * Bidding contract
    * 
    * @param {*} id - ID
    * @param {*} n - ring size (json)
    * @param {*} I - key image (point in base64)
    * @param {*} c1 - c_1 (bn in base64)
    * @param {*} s - array of s (s_1,...,s_n) (bn in base64)
    * @param {*} publickey - publickey array of ring members (point in base64)
    * @param {*} com_location - pedersen commitment of location in base64
    * @param {*} com_task - pedersen commitment of task in base64
    * @param {*} com_bidprice - pedersen commitment of bidprice in base64
    */
    async Bidding(ctx,id, n, I, c1, s, publickey, 
        com_location, com_task, com_bidprice) {
        
        //time start
        var start = Date.now();
    
        //check the duplication of ID
        const exists = await this.AssetExists(ctx, id);

        //ID duplication -> Error
        if (exists) {
            throw new Error(`ID duplication in Bidding`);
        }
    
        //split into array
        var tr_s = s.split(';');
        var tr_publickey = publickey.split(';');

        //verify result of signature
        const verify = verifyRingSignature(n,I,c1,tr_s,tr_publickey);

        //verify succeeds
        if (verify) {
            console.log('Mr Ring Signature Verified!');
        }

        //verify fails
        if (!verify) {
            throw new Error(`Signature verification fails in Bidding`);
        }
    
        //write information
        const asset = {
            //anony user id
            AUID: id,
            //commitment
            Com_location: com_location,
            Com_task: com_task,
            Com_bidprice: com_bidprice,
            //key image
            Key_image: I,
            //
        };
    
        //write to ledger
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));
    
        //time end
        var end = Date.now();
    
        //runtime output
        console.log("time of Bidding:",(end-start).toString());
    
        //bidding succeeds
        return true;
    }


    /**
    * revealbid contract
    * 
    * @param {*} id - ID
    * @param {*} publickey - signer's publickey in base64
    * @param {*} signature - submitted signature in base64
    * @param {*} location - task location in json
    * @param {*} task - task in json
    * @param {*} bidprice - bidprice in json
    * @param {*} r_location - blind factor for task location in json
    * @param {*} r_task - blind factor for task in json
    * @param {*} r_bidprice - blind factor for bidprice in json
    * @param {*} com_location - pedersen commitment of location in base64
    * @param {*} com_task - pedersen commitment of task in base64
    * @param {*} com_bidprice - pedersen commitment of bidprice in base64
    * @param {*} H_point - H point in base64
    */
    async RevealBid(ctx, id, publickey, signature, 
        location, task, bidprice,
        r_location, r_task, r_bidprice, 
        com_location, com_task, com_bidprice, 
        H_point) {
        
        //time start
        var start = Date.now();
            
        //check the duplication of ID
        const exists = await this.AssetExists(ctx, id);

        //ID duplication -> Error
        if (exists) {
            throw new Error(`ID duplication in RevealBid`);
        }

        //translation
        let signArray = StringTrans.toUint8Arr('RevealBid');
        
        //base64 to buffer
        let trans_publickey = Base64Helper.base64ToBuf(publickey);
        let trans_signature = Base64Helper.base64ToBuf(signature);

        //verify result of signature
        const verify = nacl.sign.detached.verify(signArray,trans_signature,trans_publickey);

        //verify fails
        if (!verify) {
            throw new Error(`Signature verification fails in Bidding`);
        }

        //real value | json -> number (bn)
        let tr_location = JSON.parse(location);
        let tr_task = JSON.parse(task);
        let tr_bidprice = JSON.parse(bidprice);

        //real blind factor r | json -> number (bn)
        let tr_r_location = JSON.parse(r_location);
        let tr_r_task = JSON.parse(r_task);
        let tr_r_bidprice = JSON.parse(r_bidprice);

        //commitment | base64 -> buffer
        let tr_com_location = Base64Helper.base64ToBuf(com_location);
        let tr_com_task = Base64Helper.base64ToBuf(com_task);
        let tr_com_bidprice = Base64Helper.base64ToBuf(com_bidprice);
        

        //commitment | buffer -> point
        let point_com_location = ec.curve.decodePoint(tr_com_location);
        let point_com_task = ec.curve.decodePoint(tr_com_task);
        let point_com_bidprice = ec.curve.decodePoint(tr_com_bidprice);

        //H point | base64 -> buffer
        let tr_H_point = Base64Helper.base64ToBuf(H_point);

        //H point | buffer -> point
        let point_H_point = ec.curve.decodePoint(tr_H_point);

        //pedersen commitment verification
        if (!Pedersen.verify(point_H_point, point_com_location, tr_r_location, tr_location))
            throw new Error(`Commitment verification fails in RevealBid - wrong location`);
        
        if (!Pedersen.verify(point_H_point, point_com_task, tr_r_task, tr_task))
            throw new Error(`Commitment verification fails in RevealBid - wrong task`);
        
        if (!Pedersen.verify(point_H_point, point_com_bidprice, tr_r_bidprice, tr_bidprice))
            throw new Error(`Commitment verification fails in RevealBid - wrong bidprice`);
        
        //write information
        const asset = {
            //anony user id
            AUID: id,
            //real value
            location: tr_location,
            task: tr_task,
            bidprice: tr_bidprice,
            //
        };

        //write to ledger
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));
        
        //time end
        var end = Date.now();

        //runtime output
        console.log("time of RevealBid:",(end-start).toString());
        
        //revealbid succeeds
        return true;
    }


    /*the incentive mechanism contract */
    async IM(ctx, id, x, t_taskset, t_bid, t_hk, USERNUM, TASKNUM, budget) {
        
        //time start
        var start=Date.now();

        //check the duplication of ID
        const exists = await this.AssetExists(ctx, id);

        //ID duplication -> Error
        if (exists) {
            throw new Error(`ID duplication in IM`);
        }

        //transformation
        var user_taskset = JSON.parse(t_taskset);
        var user_bid = JSON.parse(t_bid);
        var hk = JSON.parse(t_hk);

		//intilize payment array
		var payment = new Array();
		for (let i = 0; i < USERNUM; i++)
		{
			payment[i] = 0;
		}

        //intilize winner set
        var S = new Array();

        //case1
		if (x==1 || x==2){
			//case 1
			let max_value = 0;
			let e;
			for (let i = 0; i < USERNUM; i++){
				let test_S= new Array();
				test_S[0] = 1;
				test_S[1] = i;
				let this_value = Cal_f(test_S, user_taskset, TASKNUM, hk);
				if (this_value > max_value){
					max_value = this_value;
					e = i;
	    		}
			}
            S[0] = 1;
            S[1] = e;
			payment[e] = budget;
			//console.log(e);
		}

        //case2
		if (x==3 || x==4 || x==5){
			//Worker Recruitment Phase
			S[0] = 0;
			
			let e = argmax_withbid(S, 999999, S, user_taskset, user_bid, USERNUM, TASKNUM, hk);
			do{
				S[0]++;
				S[S[0]] = e;
				e=argmax_withbid(S, 999999, S, user_taskset, user_bid, USERNUM, TASKNUM, hk);
				
				//calculate f(S\cup e)
				S[0]++;
				S[S[0]] = e;
				var f_Se = Cal_f(S, user_taskset, TASKNUM, hk);
				S[0]--; //recover set S
			}while(user_bid[e] <= budget*Cal_fi_S(e, S, user_taskset, TASKNUM, hk) / 2 / f_Se);
			//console.log(S);
		
            //Payment Calculation Phase
		    for (let i = 1; i <= S[0]; i++){
			    let this_winner = S[i]; //this winner e

			    let S_pie = new Array();
			    S_pie[0] = 0;
			    do{
			    	var e_pie = argmax_withbid(S_pie, this_winner, S_pie, user_taskset, user_bid, USERNUM, TASKNUM, hk);					
                    S_pie[0]++;
			    	S_pie[S_pie[0]] = this_winner;
			    	let f_Se = Cal_f(S_pie, user_taskset, TASKNUM, hk);
	    			S_pie[0]--;
		    		let min1 = budget*Cal_fi_S(this_winner, S_pie, user_taskset, TASKNUM, hk) / 2 / f_Se;
			    	let min2 = Cal_fi_S(this_winner, S_pie, user_taskset, TASKNUM, hk) * user_bid[e_pie] / Cal_fi_S(e_pie, S_pie, user_taskset, TASKNUM, hk);
				    let min_value = Math.min(min1, min2);
				    payment[this_winner] = Math.max(payment[this_winner], min_value);
	    			S_pie[0]++;
		    		S_pie[S_pie[0]] = e_pie;
		    	}
                while(user_bid[e_pie] <= budget*Cal_fi_S(e_pie, S_pie, user_taskset, TASKNUM, hk) / 2 / Cal_f(S_pie, user_taskset, TASKNUM, hk));
            }     
		}

        //write information
        const asset = {
            ID: id,
            winner: S,
        };

        //write to ledger
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));

        var end = Date.now();

        console.log("time of IM:",(end-start).toString());

        return S+payment; 
        //return the winner set and payment set
    }


    /*data submission contract */
    async DataSubmission(ctx, id, publickey, signature, address, digest, account) {
        
        var start = Date.now();
    
        const exists = await this.AssetExists(ctx, id);
        
        if (exists) {
            throw new Error(`ID duplication in DataSubmission`);
        }
        
        //generate message
        let signArray = StringTrans.toUint8Arr('Datasubmission');

        //transformation
        let trans_publickey = Base64Helper.base64ToBuf(publickey);
        let trans_signature = Base64Helper.base64ToBuf(signature);

        //verify fails
        if (!verify) {
            throw new Error(`Signature verification fails in DataSubmission`);
        }
    
        const asset = {
            TID: id,
            Publickey: publickey,
            Address: address,
            Digest: digest,
            Account: account,
        };
    
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));

        var end = Date.now();

        console.log("time of DataSubmission:",(end-start).toString());

        return true;
    }


    /*payment contract */
    async Payment(ctx,id, pay_account, obtain_account, amount, winnernumber) {
        
        var start = Date.now();
        
        for (let i = 1; i <= winnernumber; i++){
            
            var w_id = parseInt(id) + i - 1;
            const asset = {
                TransactionID: w_id.toString(),
                pay_account: pay_account,
                obtain_account: obtain_account,
                amount: amount,
            };
             
            await ctx.stub.putState(w_id.toString(), Buffer.from(JSON.stringify(asset)));
        }
        
        var end = Date.now();

        console.log("time of Payment:",(end-start).toString());

        return true;
    }
    

    /* 
    * the ledger system for application in crowdsensing

    *
    *
    *
    *
    *
    *
    */

    // CreateAsset
    async CreateAsset(ctx, id, value) {
        const asset = {
            ID: id,
            Value: value,
        };
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));
        return JSON.stringify(asset);
    }

    // ReadAsset
    async ReadAsset(ctx, id) {
        const assetJSON = await ctx.stub.getState(id);
        if (!assetJSON || assetJSON.length === 0) {
            throw new Error(`The asset ${id} does not exist`);
        }
        return assetJSON.toString();
    }

    // UpdateAsset
    async UpdateAsset(ctx, id, value) {
        const exists = await this.AssetExists(ctx, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }

        // overwriting original asset
        const updatedAsset = {
            ID: id,
            Value: value,
        };
        return ctx.stub.putState(id, Buffer.from(JSON.stringify(updatedAsset)));
    }

    // DeleteAsset
    async DeleteAsset(ctx, id) {
        const exists = await this.AssetExists(ctx, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }
        return ctx.stub.deleteState(id);
    }

    // AssetExists
    async AssetExists(ctx, id) {
        const assetJSON = await ctx.stub.getState(id);
        return assetJSON && assetJSON.length > 0;
    }

    // TransferAsset
    async TransferAsset(ctx, id, newOwner) {
        const assetString = await this.ReadAsset(ctx, id);
        const asset = JSON.parse(assetString);
        asset.Owner = newOwner;
        return ctx.stub.putState(id, Buffer.from(JSON.stringify(asset)));
    }

    // GetAllAssets
    async GetAllAssets(ctx) {
        const allResults = [];
        // range query with empty string for startKey and endKey does an open-ended query of all assets in the chaincode namespace.
        const iterator = await ctx.stub.getStateByRange('', '');
        let result = await iterator.next();
        while (!result.done) {
            const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
            let record;
            try {
                record = JSON.parse(strValue);
            } catch (err) {
                console.log(err);
                record = strValue;
            }
            allResults.push({ Key: result.value.key, Record: record });
            result = await iterator.next();
        }
        return JSON.stringify(allResults);
    }
    
}

module.exports = Crowdsensing;
