declare namespace jsrsasign{
    export class KEYUTIL{
        static version:string;
        static getKey(param:KJUR_KeyObject, passcode?:string, hextype?:string):KeyObjects;
        static getPEM(keyObjOrHex:string|KeyObjects,formatType:string,passwd?:string,encAlg?:string,hexType?:string,ivsaltHex?:string):string;
    }
    type KeyObjects = RSAKey|KJUR.crypto.DSA|KJUR.crypto.ECDSA;
}
