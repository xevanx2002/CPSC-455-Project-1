import sha256 from "js-sha256";
// run npm install js-sha256

function hashFun(preHash, passCheck) {
    let temp = preHash;
    const saltNoPass = 'WouldYouSayThisIsABasicCaesarCipher';
    const saltPass = 'InMyProfessionalOpinion';
    
    console.log(temp);

    if(passCheck) {
        temp += saltNoPass;
    }
    else {
        temp += saltPass;
    }

    temp = sha256(temp);
    // Insert Hashing Algorithnm here and set temp to the new Hash
    console.log(temp);
    return temp;
};

export default hashFun;