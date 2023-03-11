declare namespace jsrsasign{
    declare namespace KJUR.asn1.tsp{
        class MessageImprint extends KJUR.asn1.ASN1Object{
            constructor(pram:MessageImprintPram);
        }
        class TSPParser{
            constructor();
            getTimeStampReq(h:string):TimeStampReqFields;
            getResponse(h:string):TimeSampResPram;
            getToken(h:string):TimeStampFileds;
        }
        class TimeStampReq extends KJUR.asn1.ASN1Object{
            constructor(pram:TimeStampReqPram)
        }
        class TimeStampResp extends KJUR.asn1.ASN1Object{
            constructor(pram:TimeStampResPram|TimeStampStatusPram)
        }
        class TSTInfo extends KJUR.asn1.ASN1Object{
            constructor(pram:TSTInfoPram)
        }
    }
}

type TimeStampResPram = {
    statusinfo?:PKIStatusInfo,
    version?: number,
    hashalgs?: Array<JSRSASIGN_SupportHashAlg>,
    econtent?: {
        type:"tstinfo",
        content:TSTInfoPram,
    },
    certs?:Array<string>,
    sinfos?: [{
        version: number,
        id: {type:string, issuer: JSRSASIGN_DER_OctetString, serial: JSRSASIGN_DER_Integer},
        hashalg: JSRSASIGN_SupportHashAlg,
        sattrs?: {array:Array<{ //ToDo:Check 
            attr?:string,
            str?:string,
            type?:string,
            hex?:string,
        }>},
        sigalg?: string,
        signkey?:string,
    }],
    fixed?:boolean,
}
type TimeStampFileds= {
    statusinfo?:PKIStatusInfo,
    version?: number,
    hashalgs?: Array<JSRSASIGN_SupportHashAlg>,
    econtent?: {
        type:"tstinfo",
        content:TSTInfoPram,
    },
    certs?:{array:Array<string>},
    sinfos?: [{
        version: number,
        id: {type:string, issuer: JSRSASIGN_DER_OctetString, serial: JSRSASIGN_DER_Integer},
        hashalg: JSRSASIGN_SupportHashAlg,
        sattrs?: {array:Array<{ //ToDo:Check 
            attr?:string,
            str?:string,
            type?:string,
            hex?:string,
        }>},
        sigalg?: string,
        signkey?:string,
    }],
    fixed?:boolean,
}
type TimeStampStatusPram = {
    statusinfo: {
        status: strin|number,
        statusstr?: Array<string>,
        failinfo?: string|number,
    }
}
type PKIStatusInfo = string
    |{status:string,
      statusstr: Array<string>,
      failinfo:string
    }
type TSTInfoPram = {
    policy:string,
    messageImprint:MessageImprintPram, 
    serial:JSRSASIGN_DER_Integer,
    genTime?:{str?:string,millis: boolean},
    accuracy?:Accuracy,
    ordering?:boolean,
    nonce?:JSRSASIGN_DER_Integer,
    tsa?:JSRSASIGN_DER_OctetString
}
interface MessageImprintPram{alg: string, hash:string};
interface Accuracy{
    seconds?:number,
    millis?:number,
    micros?:number,
}
interface TimeStampReqPram{
    messageImprint:MessageImprintPram,
    policy?: string,
    nonce?: {hex: string},
    certreq?: boolean
}
interface TimeStampReqFields{
    messageImprint: {
         alg: string,
         hash: string
    },
    policy?:string,
    nonce?:string
    certreq?:boolean
}