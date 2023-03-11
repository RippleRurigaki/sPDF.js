declare module 'jsrsasign'{
    export = jsrsasign;
    export function b64utohex(b64:string):string;
    export function hextob64(hex:string):string;
    export function pemtohex(pem:string):string;
    export function zulutodate(s:string):Date;
}

type JSRSASIGN_SupportHashAlg = "md5"|"sha1"|"sha224"|"sha256"|"sha384"|"sha512"|"ripemd160"|"sha256";
type JSRSASIGN_SupportSignAlg = "MD5withRSA"
    |"SHA1withRSA"
    |"SHA224withRSA"
    |"SHA256withRSA"
    |"SHA384withRSA"
    |"SHA512withRSA"
    |"RIPEMD160withRSA"
    |"MD5withECDSA"
    |"SHA1withECDSA"
    |"SHA224withECDSA"
    |"SHA256withECDSA"
    |"SHA384withECDSA"
    |"SHA512withECDSA"
    |"RIPEMD160withECDSA"
    |"MD5withRSAandMGF1"
    |"SHAwithRSAandMGF1"
    |"SHA1withRSAandMGF1"
    |"SHA224withRSAandMGF1"
    |"SHA256withRSAandMGF1"
    |"SHA384withRSAandMGF1"
    |"SHA512withRSAandMGF1"
    |"RIPEMD160withRSAandMGF1"
    |"SHA1withDSA"
    |"SHA224withDSA"
    |"SHA256withDSA";
type JSRSASIGN_KeyObject = string;

type ASN1_JSObject = {
    
    //'bool' - KJUR.asn1.DERBoolean
    int?:JSRSASIGN_DER_Integer;
    bitstr?:JSRSASIGN_DER_BitString;
    octstr?:JSRSASIGN_DER_OctetString;
    //'null' - KJUR.asn1.DERNull
    oid?:JSRSASIGN_DER_ObjectIndentifier;
    //'enum' - KJUR.asn1.DEREnumerated
    //'utf8str' - KJUR.asn1.DERUTF8String
    //'numstr' - KJUR.asn1.DERNumericString
    //'prnstr' - KJUR.asn1.DERPrintableString
    //'telstr' - KJUR.asn1.DERTeletexString
    //'ia5str' - KJUR.asn1.DERIA5String
    //'utctime' - KJUR.asn1.DERUTCTime
    //'gentime' - KJUR.asn1.DERGeneralizedTime
    //'visstr' - KJUR.asn1.DERVisibleString
    //'bmpstr' - KJUR.asn1.DERBMPString
    set?:Array<ASN1_JSObject>;
    seq?:Array<ASN1_JSObject>;
    tag?:JSRSASIGN_DER_TaggedObject;
    //'asn1' - KJUR.asn1.ASN1Object
        
}

type JSRSASIGN_DER_Integer = {int?:number,bigint?:bigint,hex?:string}
type JSRSASIGN_DER_BitString = {bin?:string,array?:Array<boolean>,hex?:string,obj?:ASN1_JSObject}
type JSRSASIGN_DER_OctetString = {str?:string,hex?:string,obj?:ASN1_JSObject}

type JSRSASIGN_DER_ObjectIndentifier = string|{oid?:string,hex?:string}

type JSRSASIGN_DER_TaggedObject = {
    tagi?:string,
    tag?:string,
    explicit?:boolean,
    hex?:string,
    obj?:ASN1_JSObject,
}

interface issuerfield{
    array:Array<X500NameArray>,
    str:string
}
type X500NameArray = Array<{type:string,value:string,ds:string}>