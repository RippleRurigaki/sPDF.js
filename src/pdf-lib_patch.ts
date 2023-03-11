/*
    The code contained in this file includes code copied and modified from pdf-lib.

    pdf-lib https://github.com/Hopding/pdf-lib
    Licensed under the MIT license.
*/
import {PDFDict, PDFNumber, PDFArray, PDFRawStream, PDFString, PDFHexString, PDFObject,PDFName,PDFRef,PDFContentStream} from "pdf-lib";
import {CharCodes,assertIs,ParseSpeeds,toUint8Array, escapeRegExp,ReparseError,StalledParserError} from "pdf-lib";
import {PDFXRefStreamParser,PDFParser,PDFObjectStreamParser} from "pdf-lib";
import {PDFSecurity,UserPermission as _UserPermission,SecurityOption} from "./PDFSecurity";
import {buffer2Hex, buffer2Str} from "./utils";

import {PDFDocument as _PDFDocument, LoadOptions as _LoadOptions, PDFContext as _PDFContext} from "pdf-lib";
export interface PDFDocument extends _PDFDocument {
    load:(pdf: string | Uint8Array | ArrayBuffer, options?: LoadOptions)=> Promise<PDFDocument>;
    create:()=> Promise<PDFDocument>;
    encrypt:(pram:{
        userPassword:string,
        ownerPassword:string,
        keyBits:128|256,
        permission:UserPermission,})=>Promise<void>,
    context:PDFContext,
}
interface PDFContext extends _PDFContext{
    _encrypt?:PDFRef,
    _reEncrypt?:(obj: number, gen: number)=>(buffer:Uint8Array)=>Uint8Array,
}
export const PDFDocument = _PDFDocument as unknown as PDFDocument;
export type UserPermission = _UserPermission;
interface LoadOptions extends _LoadOptions{
    password?:string,
    reqPermissions?:UserPermission,
    unRemoveEncryptDic?:boolean,
}
type decrypter = (encData:Uint8Array,objectNumber:number,generetionNumber:number)=>Uint8Array;

const pdf_lib_Patch = {
    PDFString_SupportUTF16:(_PDFString:any)=>{
        //Add support UTF-16encoding in PDFString.
        //If incude charcter-code>256 in value,encoding UTF-16BE(+BOM).
        _PDFString.prototype.sizeInBytes = function () {
            return stringEncode(this.value,this._noEncode).length + 2;
        };
        _PDFString.prototype.copyBytesInto = function (buffer:Uint8Array, offset:number) {
            buffer[offset++] = CharCodes.LeftParen;
            offset += copyStringIntoBuffer(this.value, buffer, offset,this._noEncode);
            buffer[offset++] = CharCodes.RightParen;
            return this.sizeInBytes();
        };
    },
    _BaseParserPatch:(_bytes:any) => {
        //Add a function with a byte name to handle byte data.
        _bytes.moveTOP = function (){
            this.line=0;this.column=0;this.idx=0
        }
        _bytes.moveEND = function (){
            while (!this.done()) {
                this.next();
            }
        }
        _bytes.prev = function () {
            const byte = this.bytes[this.idx--];
            if (byte === CharCodes.Newline) {
                this.line -= 1;
                this.column = 0;
            } else {
                this.column -= 1;
            }
            return byte;
        }
    },
    SupportEncrypt:(_PDFParser:any,_PDFDocument:any,_PDFXRefStreamParser:any)=>{
        //Add support encrypted PDF in PDFDocument.
        _PDFParser.prototype.parseStartxref = function(endOffset:number) {
            //ADD:Find Cross-Reference table offset.
            //    Necessary for Encrypt-dictionary efficient access.
            this.bytes.moveTo(endOffset);
            let offset = this.bytes.offset();
            while(offset>0){
                this.bytes.prev();
                offset = this.bytes.offset();
                const trailer = this.matchKeyword(Keywords.startxref);
                if(!trailer){
                    this.bytes.moveTo(offset);
                }else{
                    offset = this.bytes.offset();
                    this.skipWhitespaceAndComments();
                    const xrefoffset = this.parseRawInt();
                    this.skipWhitespace();
                    this.matchKeyword(Keywords.eof);
                    this.bytes.moveTo(offset-Keywords.startxref.length);
                    return xrefoffset;
                }
            }
        }
        _PDFParser.prototype.parseTrailer = function(endOffset:number) {
            //Mod from maybeParseTrailerDict()
            //  Support 'Prev','XRefStm'
            this.bytes.moveTo(endOffset);
            let offset = this.bytes.offset();
            while(offset>0 && !this.bytes.done()){
                this.bytes.next();
                offset = this.bytes.offset();
                const trailer = this.matchKeyword(Keywords.trailer);
                if(!trailer){
                    this.bytes.moveTo(offset);
                }else{
                    offset = this.bytes.offset();
                    this.skipWhitespaceAndComments();
                    const dict = this.parseDict();
                    this.bytes.moveTo(offset-Keywords.trailer.length);
                    return {
                        Root: dict.get(PDFName.of('Root')),
                        Encrypt: dict.get(PDFName.of('Encrypt')),
                        Info: dict.get(PDFName.of('Info')),
                        ID: dict.get(PDFName.of('ID')),
                        Prev: dict.get(PDFName.of('Prev')),
                        XRefStm:dict.get(PDFName.of('XRefStm')),
                    };
                }
            }
        }
        _PDFParser.prototype.parseTrailerXRefStm = function(offset:number):Array<Entry>{
            //Add: Parse Cross-Reference stream from Trailer-dictionary
            this.bytes.moveTo(offset);
            this.skipWhitespaceAndComments();
            this.parseIndirectObjectHeader();
            this.skipWhitespaceAndComments();
            const object = this.parseObject();
            //@ts-ignore
            return PDFXRefStreamParser.forStream(object).parseEntries() as Array<Entry>;
        }
        _PDFParser.prototype.parseCrossRefSection = async function(startOffset:number):Promise<Array<Entry>> {
            //Mod from maybeParseCrossRefSection()
            //  Support Cross-Reference stream,inclumental updated PDF,and use offsets access.
            const refEntries:Array<Entry> = [];
            let offset = this.bytes.offset();
            this.bytes.moveTo(startOffset);
            this.skipWhitespaceAndComments();
            this.bytes.moveTo(startOffset);
            const xrefKeyword = this.matchKeyword(Keywords.xref);
            if(!xrefKeyword){
                //XREF-Stream only,
                this.bytes.prev();
                this.skipWhitespaceAndComments();
                offset = this.bytes.offset();
                this.parseIndirectObjectHeader();
                this.skipWhitespaceAndComments();
                const dict = this.parseDict();
                this.bytes.moveTo(offset-Keywords.trailer.length);
                const trailer = {
                    Root: dict.get(PDFName.of('Root')),
                    Encrypt: dict.get(PDFName.of('Encrypt')),
                    Info: dict.get(PDFName.of('Info')),
                    ID: dict.get(PDFName.of('ID')),
                    Prev: dict.get(PDFName.of('Prev')),
                    XRefStm:dict.get(PDFName.of('XRefStm')),
                };
                if(trailer && Object.keys(this.context.trailerInfo).length === 0){
                    this.context.trailerInfo = trailer; 
                }
                const entries = this.parseTrailerXRefStm(offset);
                for(const entry of entries){
                    if(!refEntries.find(v=>{
                        if(v.ref.generationNumber === entry.ref.objectNumber){
                            return true;
                        }
                    })){
                        refEntries.push(entry);
                    }
                }
            }else if (xrefKeyword){
                //xref
                offset = this.bytes.offset();
                const trailer = this.parseTrailer(offset);
                if(trailer && Object.keys(this.context.trailerInfo).length === 0){
                    this.context.trailerInfo = trailer; 
                }
                if(trailer.XRefStm && trailer.XRefStm instanceof PDFNumber){
                    //Stream
                    offset = this.bytes.offset();
                    const entries = this.parseTrailerXRefStm(trailer.XRefStm.asNumber());
                    for(const entry of entries){
                        if(!refEntries.find(v=>{
                            if(v.ref.generationNumber === entry.ref.objectNumber){
                                return true;
                            }
                        })){
                            refEntries.push(entry);
                        }
                    }
                }
                if(trailer?.Prev){
                    offset = this.bytes.offset();
                    const entries = await this.parseCrossRefSection(trailer.Prev.asNumber());
                    for(const entry of entries){
                        if(!refEntries.find(v=>{
                            if(v.ref.generationNumber === entry.ref.objectNumber){
                                return true;
                            }
                        })){
                            refEntries.push(entry);
                        }
                    }
                    this.bytes.moveTo(offset);
                }
                this.bytes.moveTo(offset);
                this.skipWhitespaceAndComments();
                let objectNumber = -1;
                const entries:Array<Entry> = [];
                while (!this.bytes.done() && this.bytes.peek() >= 0x30 && this.bytes.peek() <= 0x39) {
                    const firstInt = this.parseRawInt();
                    this.skipWhitespaceAndComments();
                    const secondInt = this.parseRawInt();
                    this.skipWhitespaceAndComments();
            
                    const byte = this.bytes.peek();
                    if (byte === CharCodes.n || byte === CharCodes.f) {
                        const ref = PDFRef.of(objectNumber, secondInt);
                        const del = this.bytes.next();
                        entries.push({
                            ref:ref,
                            inObjectStream:false,
                            deleted:del===CharCodes.f?true:false,
                            offset:firstInt,
                        });
                        objectNumber += 1;
                    } else {
                        objectNumber = firstInt;
                    }
                    this.skipWhitespaceAndComments();
                }
                for(const entry of entries){
                    if(!refEntries.find(v=>{
                        if(v.ref.generationNumber === entry.ref.objectNumber){
                            return true;
                        }
                    })){
                        refEntries.push(entry);
                    }
                }
            }else{
                throw new Error('Cross-Reference unsupport format.')
            }
            return refEntries;
        }
        _PDFParser.prototype.parseDocument = async function(security?:{password?:string,reqPermissions?:UserPermission}) {
            //Mod: parseDocument()
            //  support Cross-Reference efficient access.
            if (this.alreadyParsed) {
                throw new ReparseError('PDFParser', 'parseDocument');
            }
            pdf_lib_Patch._BaseParserPatch(this.bytes);

            this.alreadyParsed = true;

            this.context.header = this.parseHeader();
            const bodyStartOffset = this.bytes.offset();
            
            this.bytes.moveEND();
            const refEntries:Array<Entry> = [];
            while(this.bytes.offset()>0){
                const startxref = this.parseStartxref(this.bytes.offset());
                if(startxref){
                    const entries = await this.parseCrossRefSection(startxref);
                    for(const entry of entries){
                        if(!refEntries.find(v=>{
                            if(v.ref.generationNumber === entry.ref.objectNumber){
                                return true;
                            }
                        })){
                            refEntries.push(entry);
                        }
                    }
                }
                this.bytes.prev();
            }
            if(this.context.trailerInfo.Encrypt){
                if(this.context.trailerInfo.Encrypt instanceof PDFRef){
                    const encryptXref = refEntries.find(v=>{
                        if(this.context.trailerInfo.Encrypt.objectNumber === v.ref.objectNumber){
                            return true;
                        }
                    });
                    if(!encryptXref){
                        throw Error ("Encrypt dic not found on CrossReferenceTable");
                    }
                    this.bytes.moveTo(encryptXref.offset);
                    this.skipWhitespaceAndComments();
                    this.parseIndirectObjectHeader();
                    this.skipWhitespaceAndComments();
                    const edict:PDFDict = this.parseDict();
                    const decrypter = PDFSecurity.decrypter(edict,this.context,security?.password||"",security?.reqPermissions);
                    this.context._reEncrypt = decrypter.reEncrypt;
                    this._decrypter = decrypter.decrypt;
                } 
            }
            const encrypt = this.context.trailerInfo.Encrypt
            this.context._encrypt = encrypt;

            this.bytes.moveTo(bodyStartOffset);
            let prevOffset;
            while (!this.bytes.done()) {
                await this.parseDocumentSection();
                    const offset = this.bytes.offset();
                if (offset === prevOffset) {
                    throw new StalledParserError(this.bytes.position());
                }
                prevOffset = offset;
            }
        
            this.maybeRecoverRoot();
            if(this.context._encrypt){
                delete this.context.trailerInfo.Encrypt;
            }
        
            if (this.context.lookup(PDFRef.of(0))) {
                console.warn('Removing parsed object: 0 0 R');
                this.context.delete(PDFRef.of(0));
            }
        
            return this.context;
        }
        _PDFParser.prototype.decryptValue = async function(ref:PDFRef,object:PDFObject) {
            //Add: Decrypt String and Stream
            const decrypter = this._decrypter as decrypter;
            if(object instanceof PDFDict){
                //@ts-ignore
                const type = object.dict.get(PDFName.of("Type")) as PDFName;
                //@ts-ignore
                for(const value of object.dict){
                    if((type?.asString() === "/Sig" || type?.asString() === "/DocTimeStamp") && value[0].asString() === "/Contents"){
                        //Skip SignContents
                        continue;
                    }
                    if(value[1] instanceof PDFString){
                        const valueBuffer = value[1].asBytes();
                        const data = decrypter(valueBuffer,ref.objectNumber,ref.generationNumber);
                        //@ts-ignore ,
                        value[1].value = buffer2Str(data);
                    }
                    if(value[1] instanceof PDFHexString){
                        const valueBuffer = value[1].asBytes();
                        const data = decrypter(valueBuffer,ref.objectNumber,ref.generationNumber);
                        //@ts-ignore ,
                        value[1].value = buffer2Hex(data);
                    }
                    if(value[1] instanceof PDFArray){
                        for(const item of value[1].asArray()){
                            await this.decryptValue(ref,item)
                        }
                    }
                    if(value[1] instanceof PDFDict){
                        await this.decryptValue(ref,value[1])
                    }
                }
            }
            if(object instanceof PDFRawStream){
                const valueBuffer = object.asUint8Array();
                const data = decrypter(valueBuffer,ref.objectNumber,ref.generationNumber);
                //@ts-ignore ,
                object.contents = data;
            }
            if(object instanceof PDFContentStream){
                const valueBuffer = object.getContents();
                const data = decrypter(valueBuffer,ref.objectNumber,ref.generationNumber);
                //@ts-ignore ,
                object.contentsCache.value = data;
            }
        }
        _PDFParser.prototype.parseIndirectObject = async function() {
            //Mod:parseIndirectObject()
            //  Support decrypt object.
            const ref = this.parseIndirectObjectHeader();
        
            this.skipWhitespaceAndComments();
            const object = this.parseObject();
            if(this.context._encrypt instanceof PDFRef && this._decrypter){
                const encryptDicRef = this.context._encrypt as PDFRef;
                const type = object.dict?.get(PDFName.of("Type"));
                if(type?.toString() !== "/XRef" && encryptDicRef.objectNumber !== ref.objectNumber){
                    await this.decryptValue(ref,object);
                }
            }
            this.skipWhitespaceAndComments();
        
            // TODO: Log a warning if this fails...
            this.matchKeyword(Keywords.endobj);
        
            if (
                object instanceof PDFRawStream &&
                object.dict.lookup(PDFName.of('Type')) === PDFName.of('ObjStm')
            ) {
                await PDFObjectStreamParser.forStream(
                object,
                this.shouldWaitForTick,
                ).parseIntoContext();
            } else if (
                object instanceof PDFRawStream &&
                object.dict.lookup(PDFName.of('Type')) === PDFName.of('XRef')
            ) {
                PDFXRefStreamParser.forStream(object).parseIntoContext();
            } else {
                this.context.assign(ref, object);
            }
        
            return ref;
        }
        _PDFParser.prototype.jumpNextBody = function(){
            //Add:Support incument updates PDF.
            this.skipWhitespaceAndComments();
            while (!this.matchKeyword(Keywords.eof) && !this.bytes.done()) {
                this.bytes.next();
            }
        }
        _PDFParser.prototype.parseDocumentSection = async function(){
            //Mod:parseDocumentSection()
            //  Support incument updates PDF.
            //  Optimized by adding processing in parseDocument()
            await this.parseIndirectObjects();
            this.jumpNextBody();
        
            // TODO: Can this be done only when needed, to avoid harming performance?
            this.skipJibberish();
        }
        _PDFXRefStreamParser.prototype.parseEntries = function (){
            //Mod:parseEntries()
            //  Supprot /DecodeParms
            //  Some PDFs use Predictor for Cross-Reference Stream.
            //  core/streams/decode.ts does not handle Predictor correctly.
            const entries = [];
            const [typeFieldWidth, offsetFieldWidth, genFieldWidth] = this.byteWidths;
            const DecodeParms = this.dict.get(PDFName.of("DecodeParms"));
            if(DecodeParms instanceof PDFDict){
                const Predictor = DecodeParms.get(PDFName.of("Predictor"));
                const Columns = DecodeParms.get(PDFName.of("Columns"));
                if(Predictor instanceof PDFNumber && Columns instanceof PDFNumber){
                    const predictorType = Predictor.asNumber();
                    const columnNum = Columns.asNumber();
                    this.bytes.bytes = predictor(this.bytes.slice(0,this.bytes.length),predictorType,columnNum)
                }
            }
            for (
                    let subsectionIdx = 0, subsectionLen = this.subsections.length;
                    subsectionIdx < subsectionLen;
                    subsectionIdx++
                ) {
                const { firstObjectNumber, length } = this.subsections[subsectionIdx];
            
                for (let objIdx = 0; objIdx < length; objIdx++) {
                    let type = 0;
                    for (let idx = 0, len = typeFieldWidth; idx < len; idx++) {
                        type = (type << 8) | this.bytes.next();
                    }
            
                    let offset = 0;
                    for (let idx = 0, len = offsetFieldWidth; idx < len; idx++) {
                        offset = (offset << 8) | this.bytes.next();
                    }
            
                    let generationNumber = 0;
                    for (let idx = 0, len = genFieldWidth; idx < len; idx++) {
                        generationNumber = (generationNumber << 8) | this.bytes.next();
                    }
            
                    // When the `type` field is absent, it defaults to 1
                    if (typeFieldWidth === 0) type = 1;
            
                    const objectNumber = firstObjectNumber + objIdx;
                    const entry = {
                        ref: PDFRef.of(objectNumber, generationNumber),
                        offset,
                        deleted: type === 0,
                        inObjectStream: type === 2,
                    };
            
                    entries.push(entry);
                }
            }
        
            return entries;
        }
        _PDFDocument.load = async function (
            pdf: string | Uint8Array | ArrayBuffer,
            options: LoadOptions = {},
        ) {
            //Mod:load()
            //  Support decrypt password option.
            const {
                ignoreEncryption = false,
                parseSpeed = ParseSpeeds.Slow,
                throwOnInvalidObject = false,
                updateMetadata = true,
                capNumbers = false,
            } = options;
            assertIs(pdf, 'pdf', ['string', Uint8Array, ArrayBuffer]);
            assertIs(ignoreEncryption, 'ignoreEncryption', ['boolean']);
            assertIs(parseSpeed, 'parseSpeed', ['number']);
            assertIs(throwOnInvalidObject, 'throwOnInvalidObject', ['boolean']);
        
            const bytes = toUint8Array(pdf);
            const context = await PDFParser.forBytesWithOptions(
            bytes,
            parseSpeed,
            throwOnInvalidObject,
            capNumbers,
            //@ts-ignore
            ).parseDocument({password:options?.password,reqPermissions:options?.reqPermissions});
            //@ts-ignore
            const pdfDocument = new PDFDocument(context, ignoreEncryption, updateMetadata);
            if(pdfDocument.context._encrypt && !options.unRemoveEncryptDic){
                //Delete Encrypt dic
                pdfDocument.context.delete(pdfDocument.context._encrypt);
                //delete pdfDocument.context._encrypt;
                let maxObjectNumber = 0;
                for(const object of (pdfDocument as PDFDocument).context.enumerateIndirectObjects()){
                    maxObjectNumber = Math.max(maxObjectNumber,object[0].objectNumber);
                }
                (pdfDocument as PDFDocument).context.largestObjectNumber = maxObjectNumber;
            }
            return pdfDocument;
        }
        _PDFDocument.prototype.encrypt = async function (pram:{
            userPassword:string,
            ownerPassword:string,
            keyBits:128|256,
            permission:UserPermission,}
        ) {
            //ADD:Support encrypt objects.
            const options:SecurityOption = {
                "userPassword":pram.userPassword,
                "ownerPassword":pram.ownerPassword,
                "permissions":pram.permission,
                "pdfVersion":pram.keyBits===256?"2.0":"1.7",
            }
            if(!this.context.trailerInfo.ID){
                const docID = PDFHexString.of(buffer2Hex(PDFSecurity.generateFileID(this.getInfoDict())));
                const idArray = PDFArray.withContext(this.context);
                idArray.push(docID);
                idArray.push(docID);
                this.context.trailerInfo.ID = idArray;
            }
            const security = PDFSecurity.create(this, options);
            const newSecurity = this.context.obj(security.dictionary);
            this.context.trailerInfo.Encrypt = this.context.register(newSecurity);
            const encryptDicObjectNumber = this.context.trailerInfo.Encrypt.objectNumber;
            await this.flush();
            for (const obj of this.context.enumerateIndirectObjects()){
                const ref = obj[0];
                if(ref.objectNumber !== encryptDicObjectNumber){
                    encryptValue(obj[0],obj[1],security)
                }
            }
        }
    }
}
const encryptValue = (ref:PDFRef,object:PDFObject,security:PDFSecurity) =>{
    if(object instanceof PDFDict){
        //@ts-ignore
        const type = object.dict.get(PDFName.of("Type")) as PDFName;
        //@ts-ignore
        for(const value of object.dict){
            if(type?.asString() === "/Sig" && value[0].asString() === "/Contents"){
                //Skip SignContents
                continue;
            }
            const encrypter = security.getEncryptFn(ref.objectNumber,ref.generationNumber);
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
                    encryptValue(ref,item,security)
                }
            }
            if(value[1] instanceof PDFDict){
                encryptValue(ref,value[1],security);
            }
        }
    }
    if(object instanceof PDFRawStream){
        const encrypter = security.getEncryptFn(ref.objectNumber,ref.generationNumber);
        const valueBuffer = object.asUint8Array();
        const data = encrypter(valueBuffer)
        //@ts-ignore ,
        object.contents = data;
    }
    if(object instanceof PDFContentStream){
        const encrypter = security.getEncryptFn(ref.objectNumber,ref.generationNumber);
        const valueBuffer = object.getContents();
        const data = encrypter(valueBuffer)
        //@ts-ignore ,
        object.contentsCache.value = data;
    }
}
const predictor = (buffer:Uint8Array,type:number,column:number) => {
    const rows:Array<Uint8Array> = [];
    const rowLength = Math.ceil(buffer.length / (column+1));
    for(let idx=0;idx<rowLength;idx++){
        rows.push(buffer.subarray(idx*(column+1),((idx+1)*(column+1))));
    }
    let length = column;
    for(let row=0;row<rows.length;row++){
        const filterType = rows[row][0];
        if(filterType === 1){
            //Sub
            for(let clm=2;clm<rows[row].length;clm++){
                if(typeof rows[row][clm] === "number"){
                    length++;
                    rows[row][clm] = rows[row][clm] + rows[row][clm-1];
                }
            }
        }
        if(filterType === 2 && row > 0){
            //Up
            for(let clm=1;clm<rows[row].length;clm++){
                if(typeof rows[row][clm] === "number"){
                    length++;
                    rows[row][clm] = rows[row][clm] + rows[row-1][clm];
                }
            }
        }
        if(type === 3){
            //Average
            for(let clm=1;clm<rows[row].length;clm++){
                const left = clm>2?rows[row][clm-1]:0;
                const up =   row>0?rows[row-1][clm]:0;
                if(typeof rows[row][clm] === "number"){
                    length++;
                    rows[row][clm] = rows[row][clm] + Math.floor((left+up)/2);
                }
            }
        }
        if(type === 4){
            //Paeth
            for(let clm=1;clm<rows[row].length;clm++){
                const left = clm>2?rows[row][clm-1]:0;
                const up =   row>0?rows[row-1][clm]:0;
                const upleft = (clm>2&&row>0)?rows[row-1][clm]:0;
                if(typeof rows[row][clm] === "number"){
                    length++;
                    rows[row][clm] = paethPredictor(left,up,upleft);
                }
            }
        }
    }
    const rawData = new Uint8Array(length);
    let pos = 0;
    let l = 0;
    for(const row of rows.map(v=>v.slice(1))){
        rawData.set(row,pos);
        pos += column;l++;
    }
    return rawData;
}
const paethPredictor = (left:number,up:number,upleft:number) => {
    const p = left + up + upleft;
    const pa = Math.abs(p-left);
    const pb = Math.abs(p-up);
    const pc = Math.abs(p-upleft);
    return Math.min(pa,pb,pc);
}
//PDFString Patch Utils
const copyStringIntoBuffer =  (str: string,buffer: Uint8Array,offset: number,noEncode:boolean): number => {
    const encStr = stringEncode(str,noEncode);
    const length = encStr.length;
    for (let idx = 0; idx < length; idx++) {
        buffer[offset++] = encStr[idx];
    }
    return length;
}
const stringEncode = (str:string,noEncode:boolean) =>{
    if(noEncode || checkSingleByteCode(str)){
        return new Uint8Array(Array.from(str).map(v=>v.charCodeAt(0)));
    }
    if(str.charCodeAt(0) === 0xfe && str.charCodeAt(1) === 0xff){
        //BOM UTF-16BE
        return new Uint8Array(Array.from(str).map(v=>v.charCodeAt(0)))
    }
    return stringToUTF16(str,"BE",true);
}

const checkSingleByteCode = (str:string) => {
    for(const c of Array.from(str)){
        if((c.codePointAt(0)||256)>128){
            return false;
        }
    }
    return true;
}
const stringToUTF16 = (str:string,byteOrder:"BE"|"LE",BOM?:boolean) => {
    const buffer = new Uint8Array(str.length*2+(BOM?2:0));
    let pos=0;
    if(BOM){
        if(byteOrder==="BE"){
            buffer[0] = 0xFE;
            buffer[1] = 0xFF;
        }else{
            buffer[0] = 0xFE;
            buffer[1] = 0xFF;
        }
        pos = 2;
    }
    for (const char of Array.from(str)) {
        const codePoint = char.codePointAt(0);
        if(codePoint){
            if(codePoint <=0xFFFF){
                buffer.set(get16to8(codePoint,byteOrder),pos);
                pos += 2;
            }else if(codePoint <=0x10FFFF){
                const h = (((codePoint - 0x10000) & 0x0FFC00)>>10) + 0xD800;
                buffer.set(get16to8(h,byteOrder),pos);
                pos += 2;
                const l = (codePoint & 0x03FF) + 0xDC00;
                buffer.set(get16to8(l,byteOrder),pos);
                pos += 2;
            }
        }
    }
    return buffer;
}

const get16to8 = (word:number,order:"BE"|"LE") => {
    if(order==="BE"){
        return new Uint8Array([(word&0xFF00)>>8,(word&0x00FF)]);
    }else{
        return new Uint8Array([(word&0x00FF),(word&0xFF00)>>8]);
    }
}

//pdf-lib / Keywords.ts
const { Space, CarriageReturn, Newline } = CharCodes;
const stream = [
    CharCodes.s,
    CharCodes.t,
    CharCodes.r,
    CharCodes.e,
    CharCodes.a,
    CharCodes.m,
  ];
  
  const endstream = [
    CharCodes.e,
    CharCodes.n,
    CharCodes.d,
    CharCodes.s,
    CharCodes.t,
    CharCodes.r,
    CharCodes.e,
    CharCodes.a,
    CharCodes.m,
  ];
const Keywords = {
    header: [
      CharCodes.Percent,
      CharCodes.P,
      CharCodes.D,
      CharCodes.F,
      CharCodes.Dash,
    ],
    eof: [
      CharCodes.Percent,
      CharCodes.Percent,
      CharCodes.E,
      CharCodes.O,
      CharCodes.F,
    ],
    obj: [CharCodes.o, CharCodes.b, CharCodes.j],
    endobj: [
      CharCodes.e,
      CharCodes.n,
      CharCodes.d,
      CharCodes.o,
      CharCodes.b,
      CharCodes.j,
    ],
    xref: [CharCodes.x, CharCodes.r, CharCodes.e, CharCodes.f],
    trailer: [
      CharCodes.t,
      CharCodes.r,
      CharCodes.a,
      CharCodes.i,
      CharCodes.l,
      CharCodes.e,
      CharCodes.r,
    ],
    startxref: [
      CharCodes.s,
      CharCodes.t,
      CharCodes.a,
      CharCodes.r,
      CharCodes.t,
      CharCodes.x,
      CharCodes.r,
      CharCodes.e,
      CharCodes.f,
    ],
    true: [CharCodes.t, CharCodes.r, CharCodes.u, CharCodes.e],
    false: [CharCodes.f, CharCodes.a, CharCodes.l, CharCodes.s, CharCodes.e],
    null: [CharCodes.n, CharCodes.u, CharCodes.l, CharCodes.l],
    stream,
    streamEOF1: [...stream, Space, CarriageReturn, Newline],
    streamEOF2: [...stream, CarriageReturn, Newline],
    streamEOF3: [...stream, CarriageReturn],
    streamEOF4: [...stream, Newline],
    endstream,
    EOF1endstream: [CarriageReturn, Newline, ...endstream],
    EOF2endstream: [CarriageReturn, ...endstream],
    EOF3endstream: [Newline, ...endstream],
  };
  
  export const IsDigit = new Uint8Array(256);

  interface Entry {
    ref: PDFRef;
    offset: number;
    deleted: boolean;
    inObjectStream: boolean;
  }

(()=>{
    pdf_lib_Patch.PDFString_SupportUTF16(PDFString);
    pdf_lib_Patch.SupportEncrypt(PDFParser,_PDFDocument,PDFXRefStreamParser);
})();