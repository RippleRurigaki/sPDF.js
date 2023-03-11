declare namespace jsrsasign{
    namespace KJUR.asn1.ocsp{
        class OCSPParser{
            getOCSPResponse(h:string):OCSResponseFileds
        }
        class ResponseData extends ASN1Object{
            constructor(pram:OCSResponseFileds);
        }

        class OCSPUtil{
            static getRequestHex(issuerCert:string,subjectCert:string,algName?:string):string;
        }
    }
}

interface OCSResponseFileds{
    resstatus: number,
    restype: string,
    respid: {name:{str:string}},
    prodat: string,
    array: Array<{
        certid: {alg:JSRSASIGN_SupportHashAlg,issname:string,isskey:string,sbjsn:string},
        status: {status: "good"|"unknown"|"revoked"},
        thisupdate: string }>,
    ext:Array<{extname:string, hex:string}>,
    alg: JSRSASIGN_SupportHashAlg,
    sighex: string,
    certs: Array<string>
}