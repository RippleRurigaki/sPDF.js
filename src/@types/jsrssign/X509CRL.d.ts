declare namespace jsrsasign{
    export class X509CRL {
        constructor(pram:string)
        
        hex:string;

        findRevCert(PEM:string):null|RevokeCert;
        findRevCertBySN(h:string):null|RevokeCert;
        getIssuerHex():string;
        verifySignature(pubKey:JSRSASIGN_KeyObjects):boolean;
        


    }
}

interface RevokeCert {
    sn:{hex:string},
    date:string,
    ext?:Array<{
        extname:string,
        code:number,
    }>
}