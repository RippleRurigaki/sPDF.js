declare namespace jsrsasign{
    namespace KJUR.crypto{
        class MessageDigest{
            constructor(pram:{alg:JSRSASIGN_SupportHashAlg,prov?:string});

            digest():string;
            digestHex(hex:string):void;
            digestString(str:string):void;
            static getCanonicalAlgName(alg:string):string;
            static getHashLength(alg:string):number;
            setAlgAndProvider(alg:string, prov?:string):void;
            updateHex(hex:string):void;
            updateString(str:string):void;
        }
        class Signature{
            constructor(pram:{alg:string});
            init(pram:string|jsrsasign.KeyObjects,pass?:string);
            updateHex(hex:string);
            updateString(str:string);
            verify(str:string):boolean;
        }

        class DSA{
            type:"DSA";
            isPrivate:boolean;
            isPublic:boolean; 
        }

        class ECDSA{
            type:"EC";
            isPrivate:boolean;
            isPublic:boolean;
        }

        class Util{
            static getRandomHexOfNbits(n:number):string;
        }
    }
}