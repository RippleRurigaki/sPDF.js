import {PDFNumber,PDFHexString,PDFString,PDFName,PDFObject, PDFRef, rotateDegrees, translate, drawImage, degrees, drawText, rgb, toUint8Array, PDFContentStream, StandardFonts, PDFAcroSignature, PDFArray,PDFDict,Color,PDFRawStream,escapeRegExp, PDFPage} from "pdf-lib";
import fontkit from '@pdf-lib/fontkit';
import {SignTool,IgetSignedHexOptions, DSSTable} from "./signTool";
import {buffer2Str,buffer2Hex,hex2buffer,imageFormatMagic,Log,convertCoord} from "./utils";
import {PDFDocument,UserPermission} from "./pdf-lib_patch";

const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';
const SUBFILTER_ADOBE_PKCS7_DETACHED = 'adbe.pkcs7.detached';
const SUBFILTER_ADOBE_PKCS7_SHA1 = 'adbe.pkcs7.sha1';
const SUBFILTER_ADOBE_X509_SHA1 = 'adbe.x509.rsa.sha1';
const SUBFILTER_ETSI_CADES_DETACHED = 'ETSI.CAdES.detached';
const SUBFILTER_ETSI_RFC3161 = 'ETSI.RFC3161';

const Prop_BuilderName = "SPDF.js";
const defaultHashAlgoritm = 'sha256';

interface LiteralObject {
    [name: string]: Literal | PDFObject;
}
interface LiteralArray {
    [index: number]: Literal | PDFObject;
}
type Literal =
    | LiteralObject
    | LiteralArray
    | string
    | number
    | boolean
    | null
    | undefined;
type LockFiled = {
    action:"All"
}|{
    action:"Include"|"Exclude",
    fileds:Array<string>,
}
type DocMDPPermssion = 1|2|3;
type SupportHashAlgorithm  = 'sha1'|'sha256'|'sha384'|'sha512';
interface TsaServer{
    url:string,
    hashAlg?:SupportHashAlgorithm,
    certSize?:number,
}
interface encryptOptions{
    userPassword:string,
    ownerPassword:string,
    permission:UserPermission,
    keyBits:128|256,
}
interface pdfSignOptions{
    hashAlg?:SupportHashAlgorithm,
    openPassword?:string,
    signer?:{
        Name?:string,
        Location?:string,
        Reason?:string,
        ContactInfo?:string,
    },
    signature?:{
        page:number,
        rect:{x:number,y:number,w:number,h:number},
        text?:{txt:string,size?:number,x?:number,y?:number,color?:Color,fontdata?:Uint8Array},
        image?:Uint8Array,
        reverseImgTxt?:boolean,
    },
    embeddedTimeStamp?:TsaServer;
}

interface newSignOptions extends pdfSignOptions{
    encrypt?:encryptOptions,
    DocMDP?:DocMDPPermssion,
    lock?:LockFiled,
}
interface inclumentalSignOptions extends pdfSignOptions{
    lock?:LockFiled,
}
interface addDssOptions{
    openPassword?:string,
    caCerts?:Array<string|Uint8Array>,
    crls?:Array<string|Uint8Array>,
    ignoreMissingTrustChain?:boolean,
    ignoreRevokedCert?:boolean,
    tsa:TsaServer,
}
interface timeStampOptions {
    openPassword?:string,
    tsa:TsaServer,
}
interface internalOptions extends pdfSignOptions{
    lock?:LockFiled,
    DocMDP?:DocMDPPermssion,
    embeddedTimeStamp?:TsaServer,
    ignoreMissingTrustChain?:boolean,
    ignoreRevokedCert?:boolean,
    tsa?:TsaServer,
    caCerts?:Array<string|Uint8Array>,
    crls?:Array<string|Uint8Array>,
    encrypt?:encryptOptions,
}
interface CERTIFICATEs{
    signer:{cert:string|Uint8Array,key:string|Uint8Array,keyPass?:string},
    caCerts?:Array<string|Uint8Array>,
}

interface crossReferenceTableRef{number:number,pos:number,gen:number,use:string}
type crossReferenceTableArray = Array<crossReferenceTableRef|null>;
class CrossReferenceTable{
    private table:crossReferenceTableArray;
    constructor(table:crossReferenceTableArray){
        this.table = table;
    }
    private _defragmentSection(){
        const unfragmentTable:crossReferenceTableArray = [];
        let zeroObj = false;
        let lastDeleteObj:crossReferenceTableRef|null = null;
        for(let i=0;i<this.table.length;i++){
            const ref = this.table[i]
            if(ref){
                unfragmentTable[i] = {"number":ref.number,"pos":ref.pos,"gen":ref.gen,"use":ref.use};
            }else{
                if(!zeroObj && unfragmentTable[0]){
                    unfragmentTable[0].pos = i;
                    zeroObj = true;
                }
                unfragmentTable[i] = {"number":i,"pos":i+1,"gen":65535,"use":"f"};
                lastDeleteObj = unfragmentTable[i];
            }
        }
        if(lastDeleteObj){
            lastDeleteObj.pos = 0;
        }
        return unfragmentTable;
    }
    public getArray(){
        return this.table;
    }
    public toBuf(defragment?:boolean){
        return (new TextEncoder()).encode(this.toString(defragment));
    }
    public toString(defragment?:boolean){
        let xrefTabl = "xref\x0a";
        let skip = 1;
        let contin = 0;
        let tablTemp = "";
        const _table = defragment?this._defragmentSection():this.table;
        for(let no=0;no<_table.length;no++){
            const ref = _table[no];
            if(ref){
                if(skip>0){
                    xrefTabl += `${no}`;
                    skip=0;
                }
                contin++
                tablTemp += `${ref.pos.toString().padStart(10,'0')} ${ref.gen.toString().padStart(5,'0')} ${ref.use} \x0a`;
            }else{
                if(contin>0){
                    xrefTabl += ` ${contin.toString()} \x0a${tablTemp}`;
                    tablTemp = "";
                    contin = 0;
                }
                tablTemp = "";
                skip++;
            }
        }
        xrefTabl += ` ${contin} \x0a${tablTemp}`;
        return xrefTabl;
    }
}
const regFNandNum = new RegExp("[0123456789fn]");
const regEndOfLine = new RegExp("[\x0D\x0A]");
const regSpace = new RegExp("[\x20]");
type SingType = 0|1|2;
const singType = {
    none:0 as SingType,
    signeture:1 as SingType,
    timestamp:2 as SingType,
}
export class pdfSigner{
    private signerCert?:{cert:Uint8Array,key:Uint8Array};
    private caCert?:Array<Uint8Array>;
    private dssCerts?:Array<Uint8Array>;
    private modeFlags:{
        singType:SingType;
        incremental:boolean;
        timestamp:boolean;
        dss:0|1|2;
    }
    private signerCertSize:number;
    private assumptionSignatureSize:number;
    private pdf?:{
        buf:Uint8Array,
        data:PDFDocument,
    }
    private originalPdf?:PDFDocument;
    private modPdfBuf?:Uint8Array;
    private options?:internalOptions;

    private LOG:Log;

    constructor(options?:{debug?:boolean}){
        this.signerCertSize = 0;
        this.caCert = [];
        this.modeFlags = {
            singType:singType.none,
            incremental:false,
            timestamp:false,
            dss:0,
        }
        this.assumptionSignatureSize = 0;
        this.LOG = new Log(options?.debug?1:9);
        SignTool.setdebug(options?.debug);

    }
    _setCerts = (signerCert:CERTIFICATEs) => {
        if(signerCert){
            const _cert = SignTool.getCert(signerCert.signer.cert);
            if(!SignTool.chekCertUsage(_cert)){
                throw new Error("Certificate is not usage 'digitalSignature'.");
            }
            const _key = SignTool.getKey(signerCert.signer.key,signerCert.signer.keyPass);
            this.signerCert = {
                cert:_cert,
                key:_key,
            }
            if(signerCert.caCerts){
                this.caCert = [];
                for(const caCrt of signerCert.caCerts){
                    this.caCert.push(SignTool.getCert(caCrt));
                }
            }
            const caCertsLength = (()=>{
                if(!this.caCert){
                    return 0;
                }else{
                    return this.caCert.map(v=>v.length).reduce((a,b)=>a+b,0);
                }
            })();
            this.signerCertSize = Math.ceil(512+this.signerCert.cert.length*0.75+caCertsLength*0.75);
        }
    }
    _setDssCerts = (certs:Array<string|Uint8Array>) => {
        this.dssCerts = [];
        for(const _cert of certs){
            this.dssCerts.push(SignTool.getCert(_cert));
        }
    }

    newSing = async (pdf:string | Uint8Array | ArrayBuffer,certs:CERTIFICATEs,options?:newSignOptions) => {
        this._setCerts(certs);
        this.modeFlags = {
            singType:singType.signeture,
            incremental:false,
            timestamp:false,
            dss:0,
        }
        this.options = options;
        return await this._callPdfSign(toUint8Array(pdf));
    }
    inculumentalSign = async (pdf:string | Uint8Array | ArrayBuffer,certs:CERTIFICATEs,options?:inclumentalSignOptions) => {
        this._setCerts(certs);
        this.modeFlags = {
            singType:singType.signeture,
            incremental:true,
            timestamp:false,
            dss:0,
        }
        this.options = options;
        if(this.options?.caCerts){
            this._setDssCerts(this.options.caCerts);
        }
        return await this._callPdfSign(toUint8Array(pdf));
    }
    addDSSAllCerts = async (pdf:string | Uint8Array | ArrayBuffer,options?:addDssOptions) => {
        this.modeFlags = {
            singType:singType.timestamp,
            incremental:true,
            timestamp:true,
            dss:1,
        }
        this.options = options;
        if(this.options?.caCerts){
            this._setDssCerts(this.options.caCerts);
        }
        return await this._callPdfSign(toUint8Array(pdf));
    }
    addDSSLastTimeStamp = async (pdf:string | Uint8Array | ArrayBuffer,options?:addDssOptions) => {
        this.modeFlags = {
            singType:singType.timestamp,
            incremental:true,
            timestamp:true,
            dss:2,
        }
        this.options = options;
        if(this.options?.caCerts){
            this._setDssCerts(this.options.caCerts);
        }
        return await this._callPdfSign(toUint8Array(pdf));
    }
    inculumentalTimeStamp = async (pdf:string | Uint8Array | ArrayBuffer,tsaPram:timeStampOptions) => {
        this.modeFlags = {
            singType:singType.timestamp,
            incremental:true,
            timestamp:true,
            dss:0,
        }
        this.options = tsaPram;
        return await this._callPdfSign(toUint8Array(pdf));
    }
    
    private _callPdfSign = async (pdfBuf:Uint8Array) => {
        const assumptionTsaCertSize = (this.options && (this.options.embeddedTimeStamp || this.options.tsa))?this.options?.tsa?.certSize||6144:0;
        this.assumptionSignatureSize = this.signerCertSize + assumptionTsaCertSize;
        if(this.modeFlags.incremental){
            this.pdf = {
                buf:pdfBuf,
                data:await PDFDocument.load(
                    pdfBuf
                    ,typeof this.options?.openPassword === "string"
                        ?{"password":this.options?.openPassword,unRemoveEncryptDic:true,reqPermissions:{"modifying":true,"annotating":true}}
                    :undefined),
            }
        }else{
            this.pdf = {
                buf:new Uint8Array(pdfBuf),
                data:await PDFDocument.load(
                    new Uint8Array(pdfBuf)
                    ,typeof this.options?.openPassword === "string"
                    ?{"password":this.options?.openPassword,"updateMetadata":false}
                    :{"updateMetadata":false}),
            }
        }
        const _returnBuf = await this._pdfSign();
        if(typeof _returnBuf === "number"){
            //Contents was not size enough, so it was enlarged and reprocessed.
            this.assumptionSignatureSize = _returnBuf+64;
            if(this.modeFlags.incremental){
                this.pdf = {
                    buf:pdfBuf,
                    data:await PDFDocument.load(
                        pdfBuf
                        ,typeof this.options?.openPassword === "string"
                            ?{"password":this.options?.openPassword,unRemoveEncryptDic:true,reqPermissions:{"modifying":true,"annotating":true}}
                        :undefined),
                }
            }else{
                this.pdf = {
                    buf:new Uint8Array(pdfBuf),
                    data:await PDFDocument.load(
                        new Uint8Array(pdfBuf)
                        ,typeof this.options?.openPassword === "string"
                        ?{"password":this.options?.openPassword,"updateMetadata":false}
                        :{"updateMetadata":false}),
                }
            }
            const _returnBuf2 = await this._pdfSign();
            if(typeof _returnBuf2 === "number"){
                throw new Error(`Add sign error`);
            }else{
                return _returnBuf2;
            }
        }else{
            return _returnBuf;
        }
    }
    
    private _pdfSign = async () =>{
        if(!this.pdf){
            throw new Error('PDFDocument not loaded.');
        }
        const sigName = await this._addSignatureObject();
        if(this.modeFlags.incremental){
            this.originalPdf = await PDFDocument.load(this.pdf.buf
                ,typeof this.options?.openPassword === "string"
                    ?{"password":this.options?.openPassword,"updateMetadata":false,unRemoveEncryptDic:true,reqPermissions:{"modifying":true,"annotating":true}}
                    :{"updateMetadata":false});
            this.modPdfBuf = await this._pdflibIncrementalUpdates();
        }else{
            this.modPdfBuf = await this._deFragmentXREF();
        }
        if(!this.modPdfBuf){
            throw new Error('Add placeholder fail.');
        }
        if(!this.modeFlags.singType){
            return this.modPdfBuf;
        }
        const signedPdf = await this._addsign(sigName);
        if(!signedPdf){
            throw new Error(`Add sign error`);
        }else{
            return signedPdf;
        }
    }
    private _addSignatureObject = async () =>{
        if(!this.pdf){
            throw new Error('PDFDocument not loaded.');
        }
        const pdfData = this.pdf?.data;
        const signs:Array<string> = [];
        const singRefs:Array<PDFRef> = [];
        const emmbedCerts:Array<Uint8Array> = [];
        for(const obj of pdfData.catalog.getOrCreateAcroForm().getAllFields()){
            if(obj[0] instanceof PDFAcroSignature){
                const sigT = obj[0].T();
                if(sigT){
                    singRefs.push(obj[1]);
                    signs.push(sigT instanceof PDFString?sigT.toString():sigT.decodeText());
                }
                const sigV = obj[0].V();
                if(this.modeFlags.dss === 1 && sigV instanceof PDFDict){
                    const certContents = sigV.get(PDFName.of("Contents"));
                    if(certContents instanceof PDFHexString){
                        const certContent = hex2buffer(certContents.toString().slice(1).slice(0,-1));
                        if(!certContent){
                            throw new Error('Embbed cert read error');
                        }
                        let lastZero=0;
                        for(let p=certContent.length-1;p>0;p--){
                            if(certContent[p] !==0){
                                lastZero = p;
                                break;
                            }
                        }
                        emmbedCerts.push(certContent.slice(0,lastZero+1));
                    }
                }
            }
        }
        const newSingT = (()=>{
            let i = 1;
            while(signs.includes(`(Signature${i})`)){
                i++;
            }
            return `Signature${i}`;
        })();
        const pages = pdfData.getPages();
        const pageIndex = (this.options?.signature?.page && this.options.signature.page > 0)?this.options.signature.page-1:0;
        const ByteRange = PDFArray.withContext(pdfData.context);
        ByteRange.push(PDFName.of(newSingT.padEnd(10,"*")));
        ByteRange.push(PDFName.of(DEFAULT_BYTE_RANGE_PLACEHOLDER));
        ByteRange.push(PDFName.of(DEFAULT_BYTE_RANGE_PLACEHOLDER));
        ByteRange.push(PDFName.of(DEFAULT_BYTE_RANGE_PLACEHOLDER));
        const sigPram:LiteralObject =this.modeFlags.singType === singType.timestamp?{
            Type: 'DocTimeStamp',
            Filter: 'Adobe.PPKLite',
            SubFilter: SUBFILTER_ETSI_RFC3161,
            ByteRange,
            Contents: PDFHexString.of(newSingT+'0'.repeat((this.assumptionSignatureSize-newSingT.length)*2)),
            Prop_Build:pdfData.context.obj({App:pdfData.context.obj({Name:Prop_BuilderName})}),
        }
        :{
            Type: 'Sig',
            Filter: 'Adobe.PPKLite',
            SubFilter: SUBFILTER_ADOBE_PKCS7_DETACHED,
            ByteRange,
            Contents: PDFHexString.of(newSingT+'0'.repeat((this.assumptionSignatureSize-newSingT.length)*2)),
            M: PDFString.fromDate(new Date()),
            Prop_Build:pdfData.context.obj({App:pdfData.context.obj({Name:Prop_BuilderName})}),
        }
        if(this.options?.signer){
            for(const [key,val] of Object.entries(this.options.signer)){
                if(val){
                    sigPram[key] = PDFString.of(val);
                }
            }
        }
        if(this.options?.DocMDP){
            //Create DocMDP Obj
            const DocMDP = pdfData.context.obj({
                Type:'TransformParams',
                P:PDFNumber.of(this.options.DocMDP),
                V:'1.2',
            });
            const signaturereference = pdfData.context.obj({
                Type:'SigRef',
                TransformMethod:'DocMDP',
                TransformParams:DocMDP,
            });
            const array = PDFArray.withContext(pdfData.context);
            array.push(signaturereference);
            sigPram.Reference = array;
        }
        const signatureDict = pdfData.context.obj(sigPram);
        const signatureDictRef = pdfData.context.register(signatureDict);
        if(this.options?.DocMDP){
            //Link DocMDP
            const catalog = pdfData.context.lookup(pdfData.context.trailerInfo.Root);
            const Permission = pdfData.context.obj({
                DocMDP:signatureDictRef
            });
            if(catalog){
                //@ts-ignore ; Non public method.
                catalog.set(PDFName.of("Perms"), Permission);
            }
        }
        interface wigitPram extends LiteralObject{Rect:Array<number>}
        const widgetDictPram:wigitPram = {
            Type: 'Annot',
            Subtype: 'Widget',
            FT: 'Sig',
            Rect: [0, 0, 0, 0],
            V: signatureDictRef,
            F: PDFNumber.of(getAnnotationFlags({Print:true,Hidden:false,NoView:false,Locked:true,LockedContents:true})),
            T: PDFString.of(newSingT),
            P: pages[pageIndex].ref,
            DR:pdfData.context.obj({}),
        }
        if(this.options?.lock){
            if(this.options.lock.action === "All"){
                widgetDictPram.Lock = pdfData.context.register(pdfData.context.obj({
                    Type:"SigFieldLock",
                    Action:"All",
                    P:1,
                }));
            }
            if(this.options.lock.action === "Include"){
                const _filed = PDFArray.withContext(pdfData.context);
                for(const fname of this.options.lock.fileds){
                    _filed.push(PDFString.of(fname));
                }
                widgetDictPram.Lock = pdfData.context.register(pdfData.context.obj({
                    Type:"SigFieldLock",
                    Action:"Include",
                    P:1,
                    Fields:_filed,
                }));
            }
            if(this.options.lock.action === "Exclude"){
                const _filed = PDFArray.withContext(pdfData.context);
                for(const fname of this.options.lock.fileds){
                    _filed.push(PDFString.of(fname));
                }
                widgetDictPram.Lock = pdfData.context.register(pdfData.context.obj({
                    Type:"SigFieldLock",
                    Action:"Exclude",
                    P:1,
                    Fields:_filed,
                }));
            }
        }
        if(this.options?.signature){
            //add visible sign
            //widgetDict
            const _o = this.options.signature;
            const imgFormat = imageFormatMagic(_o.image);
            const coordConverter = new convertCoord(pages[pageIndex].getSize());
            const pos = coordConverter.convertXY({x:_o.rect.x||0,y:_o.rect.y||0});
            widgetDictPram.Rect[0] = pos.xPt;
            widgetDictPram.Rect[1] = pos.yPt;
            widgetDictPram.Rect[2] = pos.xPt+coordConverter.convertMm2Pt(_o.rect.w);
            widgetDictPram.Rect[3] = pos.yPt-coordConverter.convertMm2Pt(_o.rect.h);
            const visibleSignObj = await this._makeSigObj(pages[pageIndex],{
                "x":_o.rect.x,
                "y":_o.rect.y,
                "height":_o.rect.h,
                "width":_o.rect.w,},
                {
                    "image":_o.image&&imgFormat?{
                        "data":_o.image,
                        "format":imgFormat,
                    }:undefined,
                    "text":(_o.text?.txt)?{
                        "font":_o.text.fontdata,
                        "txt":_o.text.txt,
                        "size":_o.text.size,
                    }:undefined
                }
            );
            widgetDictPram.AP = pdfData.context.obj({N:visibleSignObj});
        }
        const widgetDict = pdfData.context.obj(widgetDictPram);
        const widgetDictRef = pdfData.context.register(widgetDict);
        pages[pageIndex].node.set(PDFName.of('Annots'), pdfData.context.obj([...(this.modeFlags.incremental?singRefs:[]),widgetDictRef]));
        const sigFlag = pdfData.catalog.getOrCreateAcroForm().dict.lookup(PDFName.of('SigFlags'));
        if(this.modeFlags.incremental && sigFlag){
            pdfData.catalog.getOrCreateAcroForm().addField(widgetDictRef);
        }else{
            pdfData.catalog.set(
                PDFName.of('AcroForm'),
                pdfData.context.obj({
                SigFlags: 3,
                Fields: [widgetDictRef],
                }),
            );
        }
        if(this.modeFlags.dss){
            if(this.modeFlags.dss === 2){
                const lastTsCert = this._lastTimeStamp(this.pdf.buf);
                if(!lastTsCert){
                    throw new Error('Last timestamp not found.')
                }
                const lastTsCertBuf = hex2buffer(lastTsCert);
                if(!lastTsCertBuf){
                    throw new Error('Last timestamp contents unsupport data.')
                }
                emmbedCerts.push(lastTsCertBuf);
            }
            const chainCheckFlag = this.options?.ignoreMissingTrustChain?true:false;
            const revokeCheckFlag = this.options?.ignoreRevokedCert?true:false;
            const dssObj = new SignTool.DSS();
            if(this.options?.crls){
                dssObj.importCRLs(this.options.crls);
            }
            if(this.dssCerts){
                dssObj.importCerts(this.dssCerts);
            }
            this.LOG.debug(`Emmbed cert ${emmbedCerts.length} nums`);
            dssObj.fetchSignerCerts(emmbedCerts);
            const _setDss:DSSTable = await dssObj.getDSSTable({ignoreMissingTrustChain:chainCheckFlag,ignoreRevokedCert:revokeCheckFlag});
            await this._addDss(_setDss);
        }
        pdfData.setModificationDate(new Date());
        return newSingT;
    }
    private _makeSigObj = async (pdfPage:PDFPage,box:{width?:number,height?:number,rotaion?:number,x?:number,y?:number},
        data:{image?:{format:"JPEG"|"PNG",data:Uint8Array},
        text?:{txt:string,size?:number,font?:Uint8Array}})=>{
        const coordConverter = new convertCoord(pdfPage.getSize());
        const pos = coordConverter.convertXY({x:box.x||0,y:box.y||0});
        const dictBox = {
            rotaion:box.rotaion||0,
            width:coordConverter.convertMm2Pt(box.width||0),
            height:coordConverter.convertMm2Pt(box.height||0),
            x:pos.xPt,
            y:pos.yPt,
        }
        if(!this.pdf){
            throw new Error('PDFDocument not loaded.');
        }
        const pdfData = this.pdf.data;
        const image = data.image;
        const text = data.text;
        const imagePdf = await (async ()=>{
            if(image){
                if(image.format === "JPEG"){
                    return pdfData.embedJpg(image.data);
                }
                if(image.format === "PNG"){
                    return pdfData.embedPng(image.data);
                }
            }
            //Dummy 1x1 PNG.
            return pdfData.embedPng("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIAAAUAAeImBZsAAAAASUVORK5CYII=");
        })();
        pdfData.registerFontkit(fontkit);
        const fontObj = await pdfData.embedFont(text?.font||StandardFonts.Courier,{"subset":true});
        const resorce = { XObject: { Image: imagePdf.ref }} as  {XObject:{ Image: PDFRef },Font?:{[fname:string]:PDFRef}};
        if(fontObj){
            resorce.Font = {F0:fontObj.ref};
        }
        const dict = imagePdf.doc.context.obj({
            Type: 'XObject',
            Subtype: 'Form',
            FormType: 1,
            BBox: [0, 0,dictBox.width, dictBox.height],
            Resources: resorce,
        });
        const opt = [
            rotateDegrees(dictBox.rotaion),
            translate(0, dictBox.rotaion % 90 === 0 ? - dictBox.width : 0),
        ]
        const imageOperater = [...drawImage('Image',{
                x:0,
                y:dictBox.height,
                width:dictBox.width,
                height:dictBox.height,
                rotate:degrees(0),
                xSkew:degrees(0),
                ySkew:degrees(0),
            }),
        ];
        const textOperater = (text && fontObj)?[...drawText(fontObj.encodeText(text.txt),{
            color: this.options?.signature?.text?.color||rgb(0, 0, 0),
            font: 'F0',
            size: text.size||10,
            rotate: degrees(0),
            xSkew: degrees(0),
            ySkew: degrees(0),
            x: 0+coordConverter.convertMm2Pt(this.options?.signature?.text?.x||0),
            y: dictBox.height-coordConverter.convertMm2Pt(this.options?.signature?.text?.y||0),
        })]:[];
        if(this.options?.signature?.reverseImgTxt){
            opt.push(...textOperater);
            opt.push(...imageOperater);
        }else{
            opt.push(...imageOperater);
            opt.push(...textOperater);
        }
        const stream = PDFContentStream.of(dict,opt,false);
        return imagePdf.doc.context.register(stream);
    }
    private _addDss = async (dss:DSSTable) =>{
        if(!this.pdf){
            throw new Error('PDFDocument not loaded.');
        }
        const pdfData = this.pdf.data;
        let dssPram:Literal = {
            Type:"DSS"
        }
        const dssDict = (()=>{
            if(pdfData.catalog.lookup(PDFName.of('DSS'))){
                return pdfData.catalog.lookup(PDFName.of('DSS'))
            }else{
                const dict = pdfData.context.obj(dssPram);
                pdfData.catalog.set(PDFName.of('DSS'),pdfData.context.register(dict));
                return dict;
            }
        })();
        if(dss.crls){
            const dic = (()=>{
                //@ts-ignore
                if(dssDict?.dict?.get(PDFName.of('CRLs'))){
                    //@ts-ignore
                    return pdfData.context.lookup(dssDict?.dict?.get(PDFName.of('CRLs')));
                }else{
                    const dict = PDFArray.withContext(pdfData.context);
                    //@ts-ignore
                    dssDict.set(PDFName.of('CRLs'),pdfData.context.register(dict));
                    return dict;
                }
            })();
            if(!dic){
                throw new Error('DSS Dict create error.');
            }
            for(const data of dss.crls){
                //@ts-ignore
                dic.array.push(pdfData.context.register(pdfData.context.flateStream(data)));
            }
        }
        if(dss.ocsps){
            const dic = (()=>{
                //@ts-ignore
                if(dssDict?.dict?.get(PDFName.of('OCSPs'))){
                    //@ts-ignore
                    return pdfData.context.lookup(dssDict?.dict?.get(PDFName.of('OCSPs')));
                }else{
                    const dict = PDFArray.withContext(pdfData.context);
                    //@ts-ignore
                    dssDict.set(PDFName.of('OCSPs'),pdfData.context.register(dict));
                    return dict;
                }
            })();
            if(!dic){
                throw new Error('DSS Dict create error.');
            }
            for(const data of dss.ocsps){
                //@ts-ignore
                dic.array.push(pdfData.context.register(pdfData.context.flateStream(data)));
            }
        }
        if(dss.certs){
            const dic = (()=>{
                //@ts-ignore
                if(dssDict?.dict?.get(PDFName.of('Certs'))){
                    //@ts-ignore
                    return pdfData.context.lookup(dssDict?.dict?.get(PDFName.of('Certs')));
                }else{
                    const dict = PDFArray.withContext(pdfData.context);
                    //@ts-ignore
                    dssDict.set(PDFName.of('Certs'),pdfData.context.register(dict));
                    return dict;
                }
            })();
            if(!dic){
                throw new Error('DSS Dict create error.');
            }
            for(const data of dss.certs){
                //@ts-ignore
                dic.array.push(pdfData.context.register(pdfData.context.flateStream(data)));
            }
        }
        return;
    }
    private _deFragmentXREF = async () => {
        // If DocMDP is enabled, the signature will be invalidated if the xref (Cross-Reference Table) section is split, so this is avoided.
        // Same as if the Cross-ReferenceTable section of the original PDF is separated when adding signatures with incremental updates.
        if(!this.pdf){
            throw new Error('PDFDocument not loaded.');
        }
        if(this.options?.encrypt){
            await this.pdf.data.encrypt({
                userPassword:this.options.encrypt.userPassword,
                ownerPassword:this.options.encrypt.ownerPassword,
                permission:this.options.encrypt.permission,
                keyBits:this.options.encrypt.keyBits,
            });
        }
        //saveしないとObjectが確定しない
        const _pdfBuf = await this.pdf.data.save({"useObjectStreams":false});
        const xref = this._findXref(_pdfBuf);
        if(!xref){
            throw new Error("Cross-Reference Table find fail");
        }
        const xrefBuf = xref.table.toBuf(true);
        const newLength = _pdfBuf.length-(xref.trailerPos-xref.pos)+xrefBuf.length;
        const defragPdf = new Uint8Array(newLength);
        defragPdf.set(_pdfBuf.slice(0,xref.pos));
        defragPdf.set(xrefBuf,xref.pos);
        defragPdf.set(_pdfBuf.slice(xref.trailerPos),xref.pos+xrefBuf.length);
        return defragPdf;
    }
    private _pdflibIncrementalUpdates = async ()=>{
        //Compare two PDFDocuments and incrementally update the differences
        const orgPdf = this.originalPdf;
        const updPdf = this.pdf?.data;
        if(!orgPdf || !updPdf || !this.pdf){
            throw new Error('Inclumental update failed.')
        }
        await updPdf.save({"useObjectStreams":false});
        const originObject:{[tag:string]:[PDFRef,PDFObject]} = {};
        for(const obj of orgPdf.context.enumerateIndirectObjects()){
            originObject[obj[0].tag] = obj;
        }
        const updateObject:{[tag:string]:{ref:PDFRef,obj:PDFObject,pos:number}} = {};
        if(orgPdf.context._encrypt && !orgPdf.context._reEncrypt){
            throw new Error("unable Re-encrypt")
        }
        for(const obj of updPdf.context.enumerateIndirectObjects()){
            if(!originObject[obj[0].tag]){
                //New object
                if(orgPdf.context._encrypt && orgPdf.context._reEncrypt){
                    encryptValue(obj[0],obj[1],orgPdf.context._reEncrypt)
                }
                updateObject[obj[0].tag] = {ref:obj[0],obj:obj[1],pos:0};
            }else{
                //Mod object
                const [orign,update] = [obj.toString(),originObject[obj[0].tag].toString()];
                if(orign.length !== update.length || orign !== update){
                    if(orgPdf.context._encrypt && orgPdf.context._reEncrypt){
                        encryptValue(obj[0],obj[1],orgPdf.context._reEncrypt)
                    }
                    updateObject[obj[0].tag] = {ref:obj[0],obj:obj[1],pos:0};
                }
            }
        }
        const originEOF = this.pdf.buf.length;
        const xrefTabArray:crossReferenceTableArray = [{number:0,pos:0,gen:65535,use:"f"}];
        const addData:Array<Uint8Array> = [];
        const eooBuf = new TextEncoder().encode("\x0aendobj\x0a");
        let pos = originEOF+1;
        for(const [tag,obj] of Object.entries(updateObject)){
            obj.pos = pos;
            const tagBuf = new TextEncoder().encode(`${obj.ref.objectNumber} ${obj.ref.generationNumber} obj\x0a`);
            const addObjBuf = new Uint8Array(tagBuf.length+obj.obj.sizeInBytes()+eooBuf.length);
            addObjBuf.set(tagBuf);
            addObjBuf.set(eooBuf,tagBuf.length+obj.obj.sizeInBytes());
            obj.obj.copyBytesInto(addObjBuf,tagBuf.length);
            addData.push(addObjBuf);
            xrefTabArray[obj.ref.objectNumber] = {number:obj.ref.objectNumber,"pos":pos,"gen":obj.ref.generationNumber,use:"n"};
            pos += addObjBuf.length;
        }
        const bodySize = addData.map(v=>v.length).reduce((a,b)=>a+b,0);
        const bodyBuf = new Uint8Array(bodySize);
        let bodyPos = 0;
        for(const buf of addData){
            bodyBuf.set(buf,bodyPos);
            bodyPos += buf.length;
        }
        //Cross-Reference Tabl
        const xrefPos = pos;
        const xrefTableBuf = (new CrossReferenceTable(xrefTabArray)).toBuf();
        //Trailer
        const xref = this._findXref(this.pdf.buf);
        if(!xref){
            throw new Error("Cross-Reference Table find fail");
        }
        const prevRefPos = xref.pos;
        const originalDocIDDic = orgPdf.context.trailerInfo.ID;
        const originalDocID = (originalDocIDDic instanceof PDFArray)?
            originalDocIDDic.asArray()[0].toString():`<${SignTool.getSHA1(this.pdf.buf).toUpperCase()}>`
        //@ts-ignore; Non public propaty.
        const trailerBuf = new TextEncoder().encode(`trailer\x0a<</Prev ${prevRefPos}`
        +`/Size ${xrefTabArray.length}`
        //@ts-ignore; Non public propaty
        +`/Root ${updPdf.context.trailerInfo.Root.tag}`
        //@ts-ignore; Non public propaty
        +`/Info ${updPdf.context.trailerInfo.Info.tag}`
        +(orgPdf.context._encrypt?`/Encrypt ${orgPdf.context._encrypt?.tag}`:"")
        //@ts-ignore; Non public propaty 
        +`/ID[${originalDocID}<${SignTool.getSHA1(this.pdf.buf).toUpperCase()}>] >>\x0a`);
        const eofBuf = new TextEncoder().encode(`startxref\x0a${xrefPos}\x0a%%EOF`);
        const newPdf = new Uint8Array(1+this.pdf.buf.length+bodyBuf.length+xrefTableBuf.length+trailerBuf.length+eofBuf.length);
        newPdf.set(this.pdf.buf);
        newPdf[this.pdf.buf.length] = 0x0a;
        newPdf.set(bodyBuf,1+this.pdf.buf.length);
        newPdf.set(xrefTableBuf,1+this.pdf.buf.length+bodyBuf.length);
        newPdf.set(trailerBuf,1+this.pdf.buf.length+bodyBuf.length+xrefTableBuf.length);
        newPdf.set(eofBuf,1+this.pdf.buf.length+bodyBuf.length+xrefTableBuf.length+trailerBuf.length);
        return newPdf;
    }
    private _addsign = async (sigName:string) =>{
        const sigSize = this.assumptionSignatureSize;
        const modPdfBuf = this.modPdfBuf;
        const cert = this.signerCert;
        const caPEMs = this.caCert||[];
        if(!modPdfBuf){
            throw new Error('failed.');
        }
        const sigObj = await this._pdfBinSigObj(modPdfBuf,sigName);
        if(!sigObj){
            throw new Error('Signecture content update fail.');
        }
        const signTargetArray = new Uint8Array(sigObj.byteRangeObj[1]+sigObj.byteRangeObj[3]);
        signTargetArray.set(modPdfBuf.slice(sigObj.byteRangeObj[0],sigObj.byteRangeObj[1]));
        signTargetArray.set(modPdfBuf.slice(sigObj.byteRangeObj[2]),sigObj.byteRangeObj[1]);
        const signOption:IgetSignedHexOptions = {"hashalg":defaultHashAlgoritm}
        if(this.options?.hashAlg){
            signOption.hashalg = this.options.hashAlg;
        }
        if(this.options?.embeddedTimeStamp){
            signOption.tsa = {"URL":this.options.embeddedTimeStamp.url}
            signOption.tsa.hashalg = this.options.embeddedTimeStamp.hashAlg||defaultHashAlgoritm;
        }else if(this.options?.tsa){
            signOption.tsa = {"URL":this.options.tsa.url}
            signOption.tsa.hashalg = this.options.tsa.hashAlg||defaultHashAlgoritm;
        }
        if((this.modeFlags.timestamp || this.options?.embeddedTimeStamp) && !signOption.tsa){
            throw new Error('TSA option undefined');
        }
        let signedcert:string|undefined;
        if(this.modeFlags.singType === singType.signeture){
            if(!cert){
                throw new Error('SignerCert not set');
            }
            signedcert = await SignTool.getSignedHex({cert:cert.cert,key:cert.key,caCerts:this.caCert},signTargetArray,signOption)
        }else if(this.modeFlags.singType === singType.timestamp){
            signedcert = await SignTool.getTsaSigneture(signTargetArray,signOption.tsa?.hashalg as SupportHashAlgorithm,{url:signOption.tsa?.URL as string})
        }
        if(signedcert){
            if(signedcert.length > sigSize*2){
                return signedcert.length/2;
            }
            const signecontent = `<${signedcert}`.padEnd(sigObj.contentLen-1,'0')+'>';
            const sContentArray = new TextEncoder().encode(signecontent);
            const signedPdf = new Uint8Array(modPdfBuf.length);
            signedPdf.set(modPdfBuf.slice(sigObj.byteRangeObj[0],sigObj.byteRangeObj[1]));
            signedPdf.set(sContentArray,sigObj.byteRangeObj[1]);
            signedPdf.set(modPdfBuf.slice(sigObj.byteRangeObj[2]),sigObj.byteRangeObj[2]);
            return signedPdf;
        }
        return;
    }
    private _pdfBinSigObj = async (pdf:Uint8Array,sigName:string) => {
        const sigObj = {
            byteRangePos:{s:0,e:0},
            byteRangeObj:[0,0,0,0],
            contentLen:-1,
        }
        const flag={
            inSig:0,
            inByteRange:false,
            inContents:false,
        }
        const trigerSize = sigName.length+24;
        const byterangeTrigerReg = new RegExp(`^\\/ByteRange\\s*\\[\\s*\\/${sigName}\\**\\s*\\/`);
        const contentsTrigerReg = new RegExp(`^\\/Contents\\s*<${sigName}00`);
        for(let pos=0;pos<pdf.length;pos++){
            const v = pdf[pos];
            if(v === '/'.codePointAt(0)){
                const item = buffer2Str(pdf,pos,trigerSize);
                if(byterangeTrigerReg.test(item)){
                    flag.inByteRange = true;
                    sigObj.byteRangePos.s = pos+item.indexOf('[');
                }
                if(contentsTrigerReg.test(item)){
                    flag.inContents= true;
                    sigObj.byteRangeObj[1] = pos+item.indexOf('<');
                }
            }
            if(flag.inByteRange){
                if(v === ']'.codePointAt(0)){
                    sigObj.byteRangePos.e = pos;
                    flag.inByteRange = false;
                    flag.inSig++;
                }
                continue;
            }
            if(flag.inContents){
                if(v === '>'.codePointAt(0)){
                    sigObj.byteRangeObj[2] = pos+1;
                    sigObj.byteRangeObj[3] = pdf.length - sigObj.byteRangeObj[2];
                    sigObj.contentLen = sigObj.byteRangeObj[2]-sigObj.byteRangeObj[1];
                    flag.inContents = false;
                    flag.inSig++;
                }
                continue;
            }
        }
        const byteRageContent = `[0 ${sigObj.byteRangeObj[1]} ${sigObj.byteRangeObj[2]} ${sigObj.byteRangeObj[3]}]`.padEnd(sigObj.byteRangePos.e-sigObj.byteRangePos.s+1);
        for(let i=sigObj.byteRangePos.s;i<=sigObj.byteRangePos.e;i++){
            pdf[i] = byteRageContent.codePointAt(i-sigObj.byteRangePos.s)||0;
        }
        return flag.inSig===2?sigObj:null;
    }
    private _findXref = (pdfBuf:Uint8Array) =>{
        let eof = -1;
        let startxref = -1;
        let xrefPos = -1;
        let trailerPos = -1;
        for(let p = pdfBuf.length;p>0;p--){
            if(pdfBuf[p] === 'F'.codePointAt(0) && p > 4){
                const keyword = buffer2Str(pdfBuf,p-4,5);
                if(keyword === "%%EOF"){
                    eof = p;
                }
            }
            if(eof > 0 && pdfBuf[p] === 'f'.codePointAt(0) && p > 8){
                const keyword = buffer2Str(pdfBuf,p-8,9);
                if(keyword === "startxref"){
                    startxref = p;
                }
            }
            if(startxref > 0 && pdfBuf[p] === 'r'.codePointAt(0) && p > 6){
                const keyword = buffer2Str(pdfBuf,p-6,7);
                if(keyword === "trailer"){
                    trailerPos = p-7;
                    break;
                }
            }
        }
        if(startxref > 0){
            let numberstart=false;
            let xrefNum = "";
            for(let p=startxref;p<eof;p++){
                const s = parseInt(String.fromCodePoint(pdfBuf[p]),10);
                if(s>=0 && s<=9){
                    if(!numberstart){
                        numberstart=true;
                    }
                    xrefNum+=s.toString();
                }else if(numberstart){
                    break;
                }
            }
            if(xrefNum){
                const xrefNumber = parseInt(xrefNum,10);
                if(Number.isFinite(xrefNumber)){
                    xrefPos = xrefNumber;
                }
            }
        }
        if(xrefPos > 0){
            const keyword = buffer2Str(pdfBuf,xrefPos,4);
            const crossReferenceTable:crossReferenceTableArray = [];
            if(keyword === "xref"){
                let step = 0;
                let objectNumber = 0;
                const refLine = ["","",""];
                for(let p=xrefPos+4;p<trailerPos;p++){
                    const s = String.fromCodePoint(pdfBuf[p]);
                    if(regFNandNum.test(s)){
                        refLine[step] += s;
                    }else if(regSpace.test(s)){
                        step++;
                    }else if(regEndOfLine.test(s)){
                        if(step){
                            const pos = parseInt(refLine[0]);
                            const gen = parseInt(refLine[1]);
                            const use = refLine[2];
                            if(use){
                                if(isFinite(pos) && isFinite(gen)){
                                    crossReferenceTable[objectNumber] = {"number":objectNumber,"pos":pos,"gen":gen,"use":use};
                                    objectNumber++;
                                }
                            }else{
                                objectNumber = pos;
                                crossReferenceTable[objectNumber] = null;
                            }
                        }
                        refLine[0] = "";
                        refLine[1] = "";
                        refLine[2] = "";
                        step = 0;
                    }
                }
                return {pos:xrefPos,trailerPos:trailerPos,table:new CrossReferenceTable(crossReferenceTable)};
            }
        }
        return;
    }
    private _lastTimeStamp = (pdfBuf:Uint8Array) =>{
        let eof = -1;
        let typeDocTimeStamp = -1;
        let objPos = -1;
        for(let p = pdfBuf.length;p>0;p--){
            if(pdfBuf[p] === 'F'.codePointAt(0) && p > 4){
                const keyword = buffer2Str(pdfBuf,p-4,5);
                if(keyword === "%%EOF"){
                    if(eof > 0){
                        return;
                    }
                    eof = p;
                }
            }
            if(eof > 0 && pdfBuf[p] === 'p'.codePointAt(0) && p > 8){
                const keyword = buffer2Str(pdfBuf,p-11,12);
                if(typeDocTimeStamp < 0 && keyword === "DocTimeStamp"){
                    typeDocTimeStamp = p;
                }
            }
            if(typeDocTimeStamp > 0 && pdfBuf[p] === 'j'.codePointAt(0) && p > 6){
                const keyword = buffer2Str(pdfBuf,p-3,4);
                if(keyword === " obj"){
                    objPos = p;
                    break;
                }
            }
        }
        if(objPos > 0){
            let contentsFlg = 0;
            let contents = "";
            for(let p=objPos;p<eof-8;p++){
                const endobjKey = buffer2Str(pdfBuf,p,6);
                const contentsKey = buffer2Str(pdfBuf,p,8);
                if(endobjKey === "endobj"){
                    return;
                }
                if(contentsKey === "Contents"){
                    contentsFlg = 1;
                    p += 6;
                }
                if(contentsFlg){
                    if(contentsFlg === 1){
                        if(pdfBuf[p] === '<'.codePointAt(0)){
                            contentsFlg = 2;
                        }
                    }else if(contentsFlg === 2){
                        contents += buffer2Str(pdfBuf,p,1);
                        if(pdfBuf[p] === '>'.codePointAt(0)){
                            contentsFlg = 0;
                            break;
                        }
                    }
                }
            }
            return contents;
        }
        return;
    }
}

const getAnnotationFlags = (flags:{
    Invisible?:boolean,
    Hidden?:boolean,
    Print?:boolean,
    NoZoom?:boolean,
    NoRotat?:boolean,
    NoView?:boolean,
    ReadOnly?:boolean,
    Locked?:boolean,
    ToggleNoView?:boolean,
    LockedContents?:boolean,
}) =>{
    return 0
    +(flags.Invisible?2**0:0)
    +(flags.Hidden?2**1:0)
    +(flags.Print?2**2:0)
    +(flags.NoZoom?2**3:0)
    +(flags.NoRotat?2**4:0)
    +(flags.NoView?2**5:0)
    +(flags.ReadOnly?2**6:0)
    +(flags.Locked?2**7:0)
    +(flags.ToggleNoView?2**8:0)
    +(flags.LockedContents?2**9:0);
}
const encryptValue = (ref:PDFRef,object:PDFObject,getEncryptFn:any) =>{
    if(object instanceof PDFDict){
        //@ts-ignore
        const type = object.dict.get(PDFName.of("Type")) as PDFName;
        //@ts-ignore
        for(const value of object.dict){
            if((type?.asString() === "/Sig" || type?.asString() === "/DocTimeStamp") && value[0].asString() === "/Contents"){
                //Skip SignContents
                continue;
            }
            const encrypter = getEncryptFn(ref.objectNumber,ref.generationNumber);
            if(value[1] instanceof PDFString){
                const valueBuffer = new Uint8Array(value[1].sizeInBytes());
                value[1].copyBytesInto(valueBuffer,0);
                const data = encrypter(valueBuffer.subarray(1,valueBuffer.length-1)) as Uint8Array
                //@ts-ignore ,
                value[1].value = escapeRegExp(buffer2Str(data));
                //@ts-ignore
                value[1]._noEncode = true;
            }
            if(value[1] instanceof PDFHexString){
                const valueBuffer = value[1].asBytes();
                const data = encrypter(valueBuffer)
                //@ts-ignore ,
                value[1].value = buffer2Hex(data);
            }
            if(value[1] instanceof PDFArray){
                for(const item of value[1].asArray()){
                    encryptValue(ref,item,getEncryptFn);
                }
            }
            if(value[1] instanceof PDFDict){
                encryptValue(ref,value[1],getEncryptFn);
            }
        }
    }
    if(object instanceof PDFRawStream){
        const encrypter = getEncryptFn(ref.objectNumber,ref.generationNumber);
        const valueBuffer = object.asUint8Array();
        const data = encrypter(valueBuffer)
        //@ts-ignore ,
        object.contents = data;
    }
    if(object instanceof PDFContentStream){
        const encrypter = getEncryptFn(ref.objectNumber,ref.generationNumber);
        const valueBuffer = object.getContents();
        const data = encrypter(valueBuffer)
        //@ts-ignore ,
        object.contentsCache.value = data;
    }
}

//PDF Encrypt Tool
export const encryptPDF = async (pdf: string | Uint8Array | ArrayBuffer,encryptOptions:encryptOptions) => {
    const pdfDoc = await PDFDocument.load(pdf);
    await pdfDoc.encrypt(encryptOptions);
    return await pdfDoc.save({"useObjectStreams":false});
}
export const decryptPDF = async (pdf: string | Uint8Array | ArrayBuffer,ownerPassword:string) => {
    const pdfDoc = await PDFDocument.load(pdf,{"password":ownerPassword});
    return await pdfDoc.save({"useObjectStreams":false});
}
