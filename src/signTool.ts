import {KJUR,X509,KEYUTIL,ASN1HEX, X509CRL,zulutodate,pemtohex} from "jsrsasign";
import axios, { AxiosError } from 'axios';
import {buffer2Hex,buffer2Str,hex2buffer,Log} from "./utils";

type SupportHashAlgorithm  = JSRSASIGN_SupportHashAlg & ('sha1'|'sha256'|'sha384'|'sha512')
const defaultHashAlgoritm = 'sha256';
export interface DSSTable{
    certs:Array<Uint8Array>,
    ocsps:Array<Uint8Array>,
    crls:Array<Uint8Array>,
}
interface CertId{sn:string,issuer:string}
export interface IgetSignedHexOptions{
    hashalg?:SupportHashAlgorithm,
    tsa?:{URL:string,hashalg?:SupportHashAlgorithm,},
}
class CertChain{
    private certs:Array<Uint8Array>;
    private invalidCerts?:Array<{pem:string,subjectString:string}>;
    private allCains:boolean;
    private ignoreMissingTrustChain?:boolean;
    private ignoreRevokedCert?:boolean;

    constructor(certs:Array<Uint8Array>,options:{ignoreMissingTrustChain?:boolean,ignoreRevokedCert?:boolean}){
        this.certs = certs;
        this.allCains = false;
        this.ignoreMissingTrustChain = options.ignoreMissingTrustChain;
        this.ignoreRevokedCert = options.ignoreRevokedCert;
    }
    public getChains = async ()=> {
        this.certs.push(...(await this._getCAIssertCrt()));
        this._deduplicationCert();
        this.invalidCerts = this._checkCertChain().map(v=>{return {pem:certHex2PEM(v.hex),subjectString:v.getSubjectString()}});
        if(this.invalidCerts.length === 0){
            this.allCains = true;
        }
        return this.ignoreMissingTrustChain||this.allCains;
    }

    public getCerts = ()=>{
        if(this.ignoreMissingTrustChain||this.allCains){
            return this.certs;
        }
        return;
    }
    public getInvalidCerts = ()=>this.invalidCerts;

    public getIssuertCert = (cert:X509|string) => {
        return (()=>{
            for(const _cert of this.certs){
                const certObj = new X509(buffer2Hex(_cert));
                if(cert instanceof X509){
                    if(certObj.getSubjectHex() ===cert.getIssuerHex()){
                        const publicKey = certObj.getPublicKey();
                        if(cert.verifySignature(publicKey)){
                            return certObj;
                        }
                    }
                }else if(typeof cert === "string"){
                    if(cert.match(/^\//)){
                        if(certObj.getSubjectString() === cert){
                            return certObj;
                        }
                    }
                }
            }
        })();
    }

    public checkCRL = (crls:Array<Uint8Array>,signInfos?:Array<{signDate:Date,signerCert:Uint8Array}>) => {
        SignTool.LOG.debug(`CheckCRL`);
        SignTool.LOG.debug(`Include ${crls.length} CRLs`)
        const foundCRL:Array<boolean> = [];
        for(const _cert of this.certs){
            const cert = new X509(buffer2Hex(_cert));
            const pram = {
                issuer:cert.getIssuerHex(),
                sn:cert.getSerialNumberHex(),
                subject:cert.getSubjectHex(),
            }
            SignTool.LOG.debug(cert.getSubjectString());
            if(pram.issuer === pram.subject){
                //self sing, maybe root CA.
                SignTool.LOG.debug(" Self sign")
                foundCRL.push(true);
            }else{
                const crl = crls.filter(v=>{
                    const _X509 = new X509CRL(buffer2Hex(v));
                    if(_X509.getIssuerHex() === pram.issuer){
                        SignTool.LOG.debug(" CRL Found.");
                        const _issuer = this.getIssuertCert(cert);
                        if(!_issuer){
                            SignTool.LOG.debug(" CRL Issuer not found.");
                            return false;
                        }
                        if(!_X509.verifySignature(_issuer.getPublicKey())){
                            SignTool.LOG.debug(" CRL Issuer invalid.");
                            return false;
                        }
                        SignTool.LOG.debug("  CRL Issuer valid.");
                        return true;
                    }
                });
                if(crl.length>0){
                    let revokeInCrl = false;
                    for(const _crl of crl){
                        //Revoke check
                        const crlObj = new X509CRL(buffer2Hex(_crl));
                        const revoke = crlObj.findRevCertBySN(cert.getSerialNumberHex());
                        if(revoke){
                            SignTool.LOG.debug(" !revoked!")
                            const revokeDate = zulutodate(revoke.date);
                            if(!signInfos){
                                revokeInCrl = true;
                            }else{
                                const signer = signInfos.find(v=>{
                                    const sicert = new X509(buffer2Hex(v.signerCert));
                                    if(cert.getSubjectHex() === sicert.getSubjectHex() && cert.getSerialNumberHex() === sicert.getSerialNumberHex()){
                                        return true;
                                    }
                                });
                                SignTool.LOG.debug(`Singed date:${signer?.signDate.toString()}`)
                                if(signer &&  revokeDate.getTime() < signer.signDate.getTime()){
                                    revokeInCrl = true;
                                    SignTool.LOG.debug(` Revoked at ${revokeDate.toString()}`);
                                    continue;
                                }
                            }
                        }
                    }
                    if(revokeInCrl){
                        foundCRL.push(false);
                    }else{
                        foundCRL.push(true);
                    }
                }else{
                    SignTool.LOG.debug(" CRL not found.");
                    foundCRL.push(false);
                }
            }
        }
        return foundCRL;
    }
    public checkOCSP = (ocsps:Array<Uint8Array>) => {
        SignTool.LOG.debug(`CheckOCSP`);
        SignTool.LOG.debug(`Include ${ocsps.length} OCSPs`)
        const foundOCSP:Array<boolean> = [];
        for(const _cert of this.certs){
            const cert = new X509(buffer2Hex(_cert));
            const pram = {
                issuer:cert.getIssuerHex(),
                sn:cert.getSerialNumberHex(),
                subject:cert.getSubjectHex(),
            }
            SignTool.LOG.debug(cert.getSubjectString());
            if(pram.issuer === pram.subject){
                //self sing, maybe root CA.
                SignTool.LOG.debug(" Self sign")
                foundOCSP.push(true);
            }else{
                const ocsp = ocsps.filter(v=>{
                    try{
                        const ocspPaser = new KJUR.asn1.ocsp.OCSPParser();
                        const ocspObj = ocspPaser.getOCSPResponse(buffer2Hex(v));
                        const issuer = this.getIssuertCert(ocspObj.respid.name.str);
                        if(!issuer){
                            return false;
                        }
                        const responseData = new KJUR.asn1.ocsp.ResponseData(ocspObj);
                        const signHex = responseData.tohex();
                        const sig = new KJUR.crypto.Signature({"alg": ocspObj.alg});
                        sig.init(issuer.getPublicKey());
                        sig.updateHex(signHex);
                        if(sig.verify(ocspObj.sighex)){
                            for(const ocspCert of ocspObj.array){
                                const isname = SignTool.getHash(hex2buffer(pram.issuer),ocspCert.certid.alg);
                                if(isname === ocspCert.certid.issname && pram.sn === ocspCert.certid.sbjsn){
                                    SignTool.LOG.debug(` Found OCSP response.`)
                                    SignTool.LOG.debug(` OCSP Status:${ocspCert.status.status}`)
                                    if(ocspCert.status.status==="good"){
                                        return true;
                                    }
                                }
                            }
                        }
                        return false;
                    }catch(e){
                        return false;
                    }
                });
                if(ocsp.length>0){
                    foundOCSP.push(true);
                }else{
                    foundOCSP.push(false);
                }
            }
        }
        return foundOCSP;
    }

    private _deduplicationCert = () => {
        const _work:Array<Uint8Array> = [];
        for(const crt of this.certs){
            const cert = new X509(buffer2Hex(crt));
            if(!_work.find(v=>{
                const _x509 = new X509(buffer2Hex(v));
                if(_x509.getIssuerString() === cert.getIssuerString() && _x509.getSerialNumberHex() === cert.getSerialNumberHex()){
                    return true;
                }
            })){
                _work.push(crt)
            }
        }
        this.certs = _work;
    }

    private _getCAIssertCrt = async (subCerts?:Uint8Array):Promise<Array<Uint8Array>> => {
        try{
            const certs:Array<Uint8Array> = [];
            for(const certData of subCerts?[subCerts]:this.certs){
                const cert = new X509(buffer2Hex(certData));
                const _issuer = this.getIssuertCert(cert);
                if(_issuer){
                    continue;
                }
                const AIAInfo = cert.getExtAIAInfo();
                if(AIAInfo?.caissuer){
                    for(const caissuerUrl of AIAInfo.caissuer){
                        if(caissuerUrl){
                            SignTool.LOG.debug(`Get CA Cert:${caissuerUrl}`)
                            const caissuerCert = await getBufferFromUrl(caissuerUrl);
                            const issuerX509 = (()=>{
                                try{
                                    const txtDec = new TextDecoder();
                                    const _certStr = txtDec.decode(caissuerCert);
                                    if(_certStr.includes("-BEGIN CERTIFICATE-")){
                                        const _x509 = new X509(_certStr);
                                        return hex2buffer(_x509.hex);
                                    }else{
                                        const _x509 = new X509(certHex2PEM(buffer2Hex(caissuerCert)));
                                        return hex2buffer(_x509.hex);
                                    }
                                }catch(e){
                                    throw new Error(`${caissuerUrl} is unsupport format`);
                                }
                            })();
                            if(!issuerX509){
                                throw new Error(`${caissuerUrl} is unsupport format`);
                            }
                            certs.push(issuerX509);
                            const _issuerX509 = new X509(buffer2Hex(issuerX509));
                            if(_issuerX509.getSubjectHex() !== _issuerX509.getIssuerHex()){
                                const issuerIssuer = await this._getCAIssertCrt(issuerX509);
                                certs.push(...issuerIssuer);
                            }
                        }
                    }
                }
            }
            return certs;
        }catch(e){
            throw new Error('CaIssuers Get failed');
        }
    }
    public _checkCertChain = () => {
        const _certs:{[id:string]:{x509:X509,hasIssuercert:boolean}} = {};
        SignTool.LOG.debug(`${this.certs.length} Certs chain check`)
        const certs = this.certs.map(v=>new X509(buffer2Hex(v)));
        for(const x509 of certs){
            const _id = x509.getIssuerHex()+x509.getSerialNumberHex();
            _certs[_id] = {x509:x509,hasIssuercert:false};
        }
        for(const [id,cert] of Object.entries(_certs)){
            SignTool.LOG.debug(`Subject=${cert.x509.getSubjectString()},Issuer=${cert.x509.getIssuerString()}`)
            if(cert.x509.getSubjectHex() === cert.x509.getIssuerHex()){
                const publicKey = cert.x509.getPublicKey();
                if(cert.x509.verifySignature(publicKey)){
                    SignTool.LOG.debug(` :Self sign.`)
                    cert.hasIssuercert = true;
                }
            }else{
                const issuer = certs.filter(v=>{
                    if(cert.x509.getIssuerHex() === v.getSubjectHex()) return true;
                });
                if(issuer.length===0){
                    SignTool.LOG.debug(` :Issuer cert not found.`)
                    if(!this.ignoreMissingTrustChain){
                        throw new Error("Isuuer cert not found\r\n"+cert.x509.getSubjectString());
                    }
                }else{
                    for(const _issuer of issuer){
                        const publicKey = _issuer.getPublicKey();
                        if(cert.x509.verifySignature(publicKey)){
                            SignTool.LOG.debug(` :Issuer cert found.`)
                            cert.hasIssuercert = true;
                            break;
                        }
                    }
                }
            }
        }
        const invalidCerts:Array<X509> = []
        for(const [id,cert] of Object.entries(_certs)){
            if(!cert.hasIssuercert){
                invalidCerts.push(cert.x509)
            }
        }
        return invalidCerts;
    }
}
class DSS{
    private signInfo:Array<{signDate:Date,signerCert:Uint8Array}>;
    private crls:Array<Uint8Array>;
    private certs:Array<Uint8Array>;
    private cChain?:CertChain;

    constructor(){
        this.signInfo = [];
        this.crls = [];
        this.certs = [];
    }
    public fetchSignerCerts = (signedCMS:Array<Uint8Array>) => {
        this.signInfo = [];
        signedCMS.forEach(v=>this._fetchSignerCert(v));
    }

    private _fetchSignerCert = (signedDer:Uint8Array) => {
        SignTool.LOG.debug("fetchSignerCert");
        try{
            const cmsParser = new KJUR.asn1.cms.CMSParser();
            const tspParser = new KJUR.asn1.tsp.TSPParser();
            const cmsData = cmsParser.getCMSSignedData(buffer2Hex(signedDer));
            const certs:Array<X509> = [];
            certs.push(...(cmsData.certs?.array||[]).map(v=>new X509(buffer2Hex(SignTool.getCert(v)))));
            for(const sinfo of cmsData.sinfos){
                if(sinfo.id.type === "isssn"){
                    const signerCertObj = certs.find(v=>{
                        if(v.getIssuerString()===sinfo.id.issuer.str && v.getSerialNumberHex() === sinfo.id.serial.hex){
                            return true;
                        }
                    });
                    if(signerCertObj){
                        const signedDate = (()=>{
                            if(cmsData.sinfos[0].sattrs?.array){
                                for(const attr of cmsData.sinfos[0].sattrs?.array){
                                    if(attr.attr === 'signingTime' && attr.str){
                                        return zulutodate(attr.str);
                                    }
                                }
                            }
                            return new Date();
                        })();
                        SignTool.LOG.debug(` singned Date:${signedDate.toString()}`);
                        SignTool.LOG.debug(` singned By:${signerCertObj.getSubjectString()}`);
                        this.signInfo.push({
                            signDate:signedDate,
                            signerCert:hex2buffer(signerCertObj.hex),
                        });
                        if(sinfo?.uattrs && Array.isArray(sinfo?.uattrs?.array)){
                            //TimeStamp
                            const tTokens = sinfo.uattrs.array.filter(v=>{
                                if(v.attr==="timeStampToken"){
                                    return true;
                                }
                            });
                            for(const _tToken of tTokens){
                                if(_tToken.valhex){
                                    const tspData = tspParser.getToken(_tToken.valhex);
                                    if(tspData.certs?.array){
                                        SignTool.LOG.debug(` Timestanp Token found.`);
                                        this.certs.push(...tspData.certs?.array.map(v=>SignTool.getCert(v)));
                                    }
                                }
                            }
                        }
                        break;
                    }else{
                        throw new Error("Signer cert not found.*")
                    }
                }
            }
        }catch(e){
            throw new Error('Fetch signercert failed');
        }
    }
    public importCRLs = (crls:Array<string|Uint8Array>) => {
        this.crls.push(...crls.map(v=>SignTool.getCrl(v)));
    }
    public importCerts = (certs:Array<string|Uint8Array>) => {
        this.certs.push(...certs.map(v=>SignTool.getCert(v)));
    }
    public getDSSTable = async (pram:{ignoreMissingTrustChain:boolean,ignoreRevokedCert:boolean}) => {
        const retdss:DSSTable = {
            certs:[],
            ocsps:[],
            crls:[],
        }
        const certs:Array<CertId> = [];
        const checkCerts = [];
        checkCerts.push(...this.signInfo.map(v=>v.signerCert));
        checkCerts.push(...this.certs);
        retdss.crls.push(...this.crls);
        this.cChain = new CertChain(checkCerts,pram);
        if(!this.cChain){
            throw 0;
        }
        await this.cChain.getChains();
        const allCert = this.cChain.getCerts();
        if(!allCert){
            const _invalidPems = this.cChain.getInvalidCerts()||[];
            throw new Error('Cert trust chain not found.'+"\r\n"+_invalidPems.map(v=>v.subjectString).join("\r\n"));
        }
        for(const cert of allCert){
            const x509 = new X509(buffer2Hex(cert));
            const certId:CertId = (()=>{
                try{
                    return {
                        "issuer":x509.getIssuerHex(),
                        "sn":x509.getSerialNumberHex(),
                    }
                }catch(e){
                    throw new Error('Unsupport cert file.')
                }
            })();
            if(!certs.find(v=>{
                if(v.issuer === certId.issuer && v.sn === certId.sn){
                    return true;
                }
            })){
                certs.push(certId);
                const _buf = hex2buffer(x509.hex);
                if(_buf){
                    retdss.certs.push(_buf);
                }
                const _dss = await this._getDSS(x509);
                retdss.certs.push(..._dss.certs);
                retdss.ocsps.push(..._dss.ocsps);
                retdss.crls.push(..._dss.crls);
            }
        }
        //check
        SignTool.LOG.debug("DSS Check");
        const crlCheck = this.cChain.checkCRL(retdss.crls,this.signInfo);
        const ocspCheck = this.cChain.checkOCSP(retdss.ocsps);
        if(retdss.certs.length !== crlCheck.length || retdss.certs.length !== ocspCheck.length){
            throw new Error("DSS check certs error");
        }
        const invalidCerts = [];
        SignTool.LOG.debug('CRL,OCSP Valid result');
        for(let idx =0;idx<retdss.certs.length;idx++){
            SignTool.LOG.debug(`${idx}:${crlCheck[idx]},${ocspCheck[idx]}`);
            if(!crlCheck[idx] && !ocspCheck[idx]){
                invalidCerts.push(retdss.certs[idx]);
            }
        }
        if(!pram.ignoreMissingTrustChain && invalidCerts.length>0){
            throw new Error('DSS invalid.')
        }
        return retdss;
    }
    private _getDSS = async (subjectCertX509:X509) => {
        const retdss:DSSTable = {
            certs:[],
            ocsps:[],
            crls:[],
        }
        if(!this.cChain){
            throw 0;
        }
        const cdpList = subjectCertX509.getExtCRLDistributionPoints();
        for(const cdp of cdpList?.array||[]){
            if(!cdp.dpname){
                continue;
            }
            const uriList:Array<string> = cdp.dpname.full.map(v=>v.uri);
            for(const uri of uriList){
                const _url = new URL(uri);
                if(_url){
                    SignTool.LOG.debug(`Get CRL:${_url.href}`)
                    const crl = await axios({url:_url.href,responseType:"arraybuffer",});
                    if(crl.status !== 200){
                        throw new Error(`Request ${_url.href} is response error.(code:${crl.status})`)
                    }else{
                        retdss.crls.push(SignTool.getCrl(crl.data));
                    }
                }
            }
        }
        const AIAInfo = subjectCertX509.getExtAIAInfo();
        if(AIAInfo && Array.isArray(AIAInfo.ocsp)){
            for(let i=0;i<AIAInfo.ocsp.length;i++){
                const ocspUrl = AIAInfo.ocsp[i];
                if(ocspUrl){
                    try{
                        const issuerX509 = this.cChain.getIssuertCert(subjectCertX509);
                        if(!issuerX509){
                            throw new Error('OCSP Issuer cert not found.');
                        }
                        const ocspRequest = KJUR.asn1.ocsp.OCSPUtil.getRequestHex(certHex2PEM(issuerX509.hex),certHex2PEM(subjectCertX509.hex));
                        SignTool.LOG.debug(`Request OCSP:${ocspUrl}`)
                        const ocspResponse = await axios({
                            "url":ocspUrl,
                            "method":"POST",
                            "data":hex2buffer(ocspRequest),
                            "responseType":"arraybuffer",
                            "headers":{"Content-Type":"application/ocsp-request"}
                        });
                        if(ocspResponse.status !== 200){
                            throw new Error(`OCSP request error [${ocspResponse.status}]\r\n${ocspResponse.data}`)
                        }
                        retdss.ocsps.push(ocspResponse.data);
                        break;
                    }catch(e){
                        if(AIAInfo.ocsp.length-i<=1){
                            if(typeof e === "string"){
                                throw new Error(e);
                            }else if(e instanceof AxiosError){
                                throw new Error(e.message)
                            }else{
                                throw new Error(`${ocspUrl} request unknow error`);
                            }
                        }
                    }
                }
            }
        }
        return retdss;
    }
}

export class SignTool{
    static LOG:Log = new Log(9);
    static setdebug = (debug?:boolean) => {
        SignTool.LOG = new Log(debug?1:9);
    }
    static getHash = (buf:Uint8Array,alg:JSRSASIGN_SupportHashAlg) => {
        const hex = buffer2Hex(buf);
        const md = new KJUR.crypto.MessageDigest({alg:alg});
        md.updateHex(hex);
        const digest = md.digest();
        return digest;
    }

    static  getSHA1 = (buf:Uint8Array):string=>{
        return SignTool.getHash(buf,"sha1");
    }

    static getSignedHex = async (
        signer:{cert:Uint8Array,key:Uint8Array,passphrase?:string,caCerts?:Array<Uint8Array>},
        target:Uint8Array,
        options?:IgetSignedHexOptions):Promise<string|undefined>=>{
            SignTool.LOG.debug("getSignedHex")
        const certObj  = new X509(buffer2Hex(signer.cert));
        const issuer = {str: certObj.getIssuer().str, serial: certObj.getSerialNumberHex()};
        const keyObj = KEYUTIL.getKey(buffer2Hex(signer.key),signer.passphrase,"pkcs8prv");
        const keyType = keyObj.type==='EC'?'ECDSA':keyObj.type;
        const hashAlg = options?.hashalg||defaultHashAlgoritm;
        const signAlg = `${hashAlg.toUpperCase()}with${keyType}`;
        const targetHash = SignTool.getHash(target,hashAlg);
        const params:{certs:string[]} & SignPrams = {
            version: 1,
            hashalgs: [hashAlg],
            econtent: {
                type: "data",
                content: {
                hex: '',
                },
                isDetached: true
            },
            certs: [certHex2PEM(certObj.hex)],
            sinfos: [{
                version: 1,
                id: {type:'isssn', issuer: {str: issuer.str}, serial: {hex: issuer.serial}},
                hashalg: hashAlg,
                sattrs: {array: [{
                    attr: "contentType",
                    type: '1.2.840.113549.1.7.1',
                },{
                    attr: "signingTime",
                    str: SignTool.getTimeStr(),
                },{
                    attr: "messageDigest",
                    hex: targetHash,
                },{
                    attr:"signingCertificateV2",
                    array:[certObj.hex],
                }
            ]},
            sigalg: signAlg,
            signkey:keyObj,
            }],
            fixed: true
        };
        if(signer.caCerts){
            params.certs.push(...signer.caCerts.map(v=>certHex2PEM(new X509(buffer2Hex(v)).hex)));
        }
        if(options?.tsa){
            SignTool.LOG.debug("Cert embeddedTimeStamp");
            const signedData = new KJUR.asn1.cms.SignedData(params);
            const cmsParser = new KJUR.asn1.cms.CMSParser();
            const _pram = cmsParser.getCMSSignedData(signedData.getContentInfoEncodedHex());
            const signedHash = _pram.sinfos[0].sighex;
            if(!signedHash){
                throw new Error(`SignatureValue not found`);
            }
            const tstInfoHex = await SignTool.getTsaSigneture(hex2buffer(signedHash),options.tsa.hashalg||defaultHashAlgoritm,{url:options.tsa.URL});
            if(!signedData.params.sinfos[0].uattrs?.array){
                signedData.params.sinfos[0].uattrs = {array:[{attr:"timeStampToken",tst:tstInfoHex}]}
            }else{
                signedData.params.sinfos[0].uattrs.array.push({attr:"timeStampToken",tst:tstInfoHex});
            }
            return signedData.getContentInfoEncodedHex();
        }else{
            const sidnedData = new KJUR.asn1.cms.SignedData(params);
            return sidnedData.getContentInfoEncodedHex();
        }
    }
    public static getTsaSigneture = async (signTrg:Uint8Array,tsaHashAlg:SupportHashAlgorithm,tsaServer:{url:string}):Promise<string> => {
        try{
            const nonceHex = KJUR.crypto.Util.getRandomHexOfNbits(32);
            const reqNonce = nonceHex.substring(/[1-9]/.exec(nonceHex)?.index||0);
            const sidnedDataHash = SignTool.getHash(signTrg,tsaHashAlg);
            const tsreqPram:TimeStampReqPram = {
                messageImprint: {alg:tsaHashAlg, hash: sidnedDataHash},
                nonce: {hex:reqNonce.length%2?`0${reqNonce}`:reqNonce},
                certreq: true,
            };
            const tsaReqData = new KJUR.asn1.tsp.TimeStampReq(tsreqPram);
            //TSA Request
            SignTool.LOG.debug(`Request TSA:${tsaServer.url}`);
            const tsaReq = await axios({
                "url":tsaServer.url,
                "method":"POST",
                "data":hex2buffer(tsaReqData.getEncodedHex()),
                "responseType":"arraybuffer",
                "headers":{"Content-Type":"application/timestamp-query"}
            })
            if(tsaReq.status !== 200){
                throw new Error(`TSA request error [${tsaReq.status}]\r\n${tsaReq.data}`)
            }
            const parser = new KJUR.asn1.tsp.TSPParser();
            const tstRes = parser.getResponse(buffer2Hex(tsaReq.data));
            if(tstRes.statusinfo === "granted"|| (typeof tstRes.statusinfo !=="string" && tstRes.statusinfo?.status === "granted")){
                const _resnonceHex = tstRes.econtent?.content?.nonce?.hex;
                if(!_resnonceHex){
                    throw new Error(`TSA response nonce invalid.`);
                }
                const resNonce = _resnonceHex.substring(/[1-9]/.exec(_resnonceHex)?.index||0);
                if(reqNonce.toLowerCase() === resNonce.toLowerCase()){
                    const tstInfoObj = ASN1HEX.parse(buffer2Hex(tsaReq.data));
                    if(tstInfoObj.seq){
                        return KJUR.asn1.ASN1Util.jsonToASN1HEX(tstInfoObj.seq[1]);
                    }
                    throw new Error(`TSA response invalid format.`);
                }else{
                    throw new Error(`TSA response nonce invalid.`);
                }
            }else if(tstRes.status === "rejection"){
                throw new Error(`TSA reject request.`);
            }else{
                throw new Error(`Unsupport format response.`);
            }
        }catch(e){
            throw new Error("Request TSA server Failed.")
        }
    }

    private static getTimeStr = () =>{
        const n = new Date();
        return `${n.getUTCFullYear().toString().slice(2).padStart(2,'0')}${(n.getUTCMonth()+1).toString().padStart(2,'0')}${n.getUTCDate().toString().padStart(2,'0')}${n.getUTCHours().toString().padStart(2,'0')}${n.getUTCMinutes().toString().padStart(2,'0')}${n.getUTCSeconds().toString().padStart(2,'0')}Z`;
    }
    public static DSS = DSS;
    public static getCert = (cert:string|Uint8Array) => {
        try{
            if(typeof cert === "string"){
                return hex2buffer(new X509(cert).hex);
            }else{
                const str = buffer2Str(cert);
                if(str.includes("-----BEGIN")){
                    return hex2buffer(new X509(str).hex);
                }else{
                    return hex2buffer(new X509(buffer2Hex(cert)).hex);
                }
            }
        }catch(e){
            throw new Error('Unsupport Certificate file.');
        }
    }
    public static chekCertUsage = (cert:Uint8Array) => {
        try{
            const x509 = new X509(buffer2Hex(cert));
            const usage = x509.getExtKeyUsage();
            const usageEx = x509.getExtExtKeyUsage();
            if(!usage && !usageEx){
                return true;
            }
            if(([...usage?usage.names:[],...usageEx?usageEx.array:[]].includes("digitalSignature"))){
                return true;
            };
            return false;
        }catch(e){
            throw new Error("Unsupport cert file.");
        }
    
    }
    public static getKey = (key:string|Uint8Array,pass?:string) => {
        try{
            if(typeof key === "string"){
                return hex2buffer(pemtohex(KEYUTIL.getPEM(KEYUTIL.getKey(key,pass),"PKCS8PRV")));
            }else{
                const str = buffer2Str(key);
                if(str.includes("-----BEGIN")){
                    return hex2buffer(pemtohex(KEYUTIL.getPEM(KEYUTIL.getKey(str,pass),"PKCS8PRV")));
                }else{
                    return hex2buffer(pemtohex(KEYUTIL.getPEM(KEYUTIL.getKey(buffer2Hex(key),pass),"PKCS8PRV")));
                }
            }
        }catch(e){
            throw new Error('Unsupport KEY file.');
        }
    }
    public static getCrl = (crl:string|Uint8Array) => {
        try{
            if(typeof crl === "string"){
                return hex2buffer(new X509CRL(crl).hex);
            }else{
                const str = buffer2Str(crl);
                if(str.includes("-----BEGIN")){
                    return hex2buffer(new X509CRL(str).hex);
                }else{
                    return hex2buffer(new X509CRL(buffer2Hex(crl)).hex);
                }
            }
        }catch(e){
            throw new Error('Unsupport CRL file.');
        }
    }
}
const certHex2PEM = (h:string) => {
    return KJUR.asn1.ASN1Util.getPEMStringFromHex(h,"CERTIFICATE")
}
const getBufferFromUrl = async (url:string) => {
    try{
        const httpResponse = await axios({url:url,responseType:"arraybuffer",});
        if(httpResponse.status !== 200){
            throw new Error(`Request ${url} is response error.(code:${httpResponse.status})`)
        }
        return httpResponse.data as Uint8Array;
    }catch(e){
        if(typeof e === "string"){
            throw new Error(e);
        }else if(e instanceof AxiosError){
            throw new Error(e.message)
        }else{
            throw new Error(`${url} request unknow error`);
        }
    }
}