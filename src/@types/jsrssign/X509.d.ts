declare namespace jsrsasign{
    export class X509 {
        constructor(pram?:string);

        hex:string;
        
        getExtAIAInfo():AIAExtensionPrams;
        getExtCRLDistributionPoints():CRLDistributionPointsPrams;
        getExtSubjectKeyIdentifier():{extname: 'subjectKeyIdentifier',kid: { hex:string}};
        getInfo():string;
        getIssuer(flagCanon?:boolean,flagHex?:boolean):issuerfield;
        getIssuerHex():string;
        getIssuerString():string;
        getExtKeyUsage():undefined|KeyUsageStr;
        getExtExtKeyUsage():undefined|ExKeyUsageStr;
        getPublicKey():JSRSASIGN_KeyObjects;
        getSerialNumberHex():string;
        getSubjectString():string;
        getSubjectHex():string;
        verifySignature(JSRSASIGN_KeyObjects):boolean;

        static readCertPEM(sCertPEM:string):X509;

    }
}

interface AIAExtensionPrams{
    ocsp:Array<string>,
    caissuer:Array<string>,
}

interface CRLDistributionPointsPrams{
    array: Array<{dpname: {full: Array<{uri: string}>}}>,
    critical: boolean
}

interface KeyUsageStr{
    critical: boolean,
    names:Array<string>,
}
interface ExKeyUsageStr{
    critical: boolean,
    array:Array<string>,
}