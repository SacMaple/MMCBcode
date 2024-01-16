'use strict';

//for base translation
let base = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/*buf &string translation */
class Base64Helper {

    instance = new Base64Helper();
    constructor() {    }

    // buf to base64(3->4)
    static bufToBase64(buf) {
        let encoded_str = '';
        let mod = buf.length % 3;
        let sum = Math.floor(buf.length / 3);

        // console.log(mod, sum, buf.length)
        for (let i = 0; i < sum * 3; i += 3) {
            let idx1, idx2, idx3;
            idx1 = i;
            idx2 = i + 1;
            idx3 = i + 2;
            let byte1, byte2, byte3, byte4;
            // 
            byte1 = buf[idx1] >> 2;
            // 
            byte2 = ((buf[idx1] & 0x03) << 4) | ((buf[idx2]) >> 4);
            // 
            byte3 = ((buf[idx2] & 0xf) << 2) | (buf[idx3]) >> 6;
            // 
            byte4 = (buf[idx3] & 0x3f);
            encoded_str += base[byte1] + base[byte2] + base[byte3] + base[byte4];
        }

        if (mod == 1) {
            let byte1, byte2, byte3, byte4;
            // 
            byte1 = buf[buf.length - 1] >> 2;
            // 
            byte2 = (buf[buf.length - 1] & 0x03) << 4;
            encoded_str += base[byte1] + base[byte2] + '=' + '=';
        } else if (mod == 2) {
            let byte1, byte2, byte3, byte4;
            // 
            byte1 = buf[buf.length - 2] >> 2;
            // 
            byte2 = ((buf[buf.length - 2] & 0x03) << 4) | ((buf[buf.length - 1]) >> 4);
            // 
            byte3 = ((buf[buf.length - 1] & 0x0f) << 2);
            encoded_str += base[byte1] + base[byte2] + base[byte3] + '=';
        }
        return encoded_str
    }


    // base64 to buffer（4->3）
    static base64ToBuf(base64Data) {
        // base64Data.
        let equalCount = base64Data.match(/=/g) || 0;
        base64Data = base64Data.replace(/=/g, '');
        let len = base64Data.length;
        let mod = len % 4;
        let sum = Math.floor(len / 4);
        let idx = 0;
        let moreLen = 0;
        if (equalCount && equalCount.length == 1) moreLen = 2;
        if (equalCount && equalCount.length == 2) moreLen = 1;
        let buf = new Uint8Array(sum * 3 + moreLen);
        for (let i = 0; i < sum * 4; i += 4) {
            let char0 = base64Data[i];
            let char1 = base64Data[i + 1];
            let char2 = base64Data[i + 2];
            let char3 = base64Data[i + 3];
            let charIdx0 = base.indexOf(char0);
            let charIdx1 = base.indexOf(char1);
            let charIdx2 = base.indexOf(char2);
            let charIdx3 = base.indexOf(char3);
            if (charIdx0 == -1 || charIdx1 == -1 || charIdx2 == -1 || charIdx3 == -1) {
                continue;
            }
            
            // 
            buf[idx++] = (charIdx0 << 2) | (charIdx1 >> 4 & 0x03);
            buf[idx++] = (charIdx1 << 4) | (charIdx2 >> 2 & 0x0f);
            buf[idx++] = (charIdx2 << 6) | (charIdx3 & 0x3f);
        }

        if (equalCount && equalCount.length > 0) {
            if (equalCount.length == 1) {
                let charIdx0 = base.indexOf(base64Data[base64Data.length - 3]);
                let charIdx1 = base.indexOf(base64Data[base64Data.length - 2]);
                let charIdx2 = base.indexOf(base64Data[base64Data.length - 1]);
                //  
                buf[buf.length - 2] = (charIdx0 << 2) | (charIdx1 >> 4);
                buf[buf.length - 1] = (charIdx1 << 4) | (charIdx2 >> 2);
            } else if (equalCount.length == 2) {
                // 
                let charIdx0 = base.indexOf(base64Data[base64Data.length - 2]);
                let charIdx1 = base.indexOf(base64Data[base64Data.length - 1]);
                buf[buf.length - 1] = (charIdx0 << 2) | (charIdx1 >> 4);
            }
        }
        return Buffer.from(buf);
    }

}

module.exports = Base64Helper;