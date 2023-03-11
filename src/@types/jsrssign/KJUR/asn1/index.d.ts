declare namespace jsrsasign{
    declare namespace KJUR.asn1{
        class ASN1Object{
            constructor(pram);

            hL:string;
            hT:string;
            hTV:string;
            hV:string;
            isModified:boolean;
            params:Array<ASN1_JSObject>;

            getEncodedHex():string;
            getLengthHexFromValue():string;
            getValueHex():string;
            tohex():string
        }
    }

    declare namespace KJUR.asn1.ASN1Util{
        function getPEMStringFromHex(dataHex:string,pemHeader:string):string;
        function jsonToASN1HEX(pram:ASN1_JSObject):string;
        function newObject(pram:JSRSASIGN_ASN1Object):ASN1_JSObject;
    }
}
