export const buffer2Str = (b:Uint8Array,pos?:number,len?:number) =>{
    const _str:Array<string> = [];
    const _pos = pos||0;
    const _len = len||b.length;
    for(let i=0;i<_len;i++){
        if(typeof b[_pos+i] === "number"){
            _str.push(String.fromCodePoint(b[_pos+i]))
        }
    }
    return _str.join('');
}
export const str2Bufeer = (str:string) =>{
    let _str = "";
    for(const c of Array.from(str)){
        const code = c.charCodeAt(0);
        if(code<256){
            _str += code.toString(16).padStart(2,"0");
        }else{
            _str += ((code&0xFF00)>>8).toString(16).padStart(2,"0");
            _str += ((code&0x00FF)).toString(16).padStart(2,"0");
        }
    }
    return hex2buffer(_str);
}
export const buffer2Hex = (b:Uint8Array,pos?:number,len?:number) =>{
    const _str:Array<string> = [];
    const _pos = pos||0;
    const _len = len||b.length;
    for(let i=0;i<_len;i++){
        if(typeof b[_pos+i] === "number"){
            _str.push(b[_pos+i].toString(16).padStart(2,'0'))
        }
    }
    return _str.join('');
}
export const hex2buffer = (hex:string) => {
    const hexMap = hex.match(/.{1,2}/g);
    if(!hexMap){
        return new Uint8Array();
    }
    return Uint8Array.from(hexMap.map((byte) => parseInt(byte, 16)));
}
export const imageFormatMagic = (img?:Uint8Array) => {
    if(!img||img.length<5){
        return;
    }
    if(img[0]===0x89 && img[1]===0x50 && img[2]===0x4e && img[3]=== 0x47){
        return "PNG";
    }
    if(img[0]===0xff && img[1]===0xd8){
        return "JPEG";
    }
    return;
}

export const logLevel={
    debug:1,
    none:9,
}
export class Log {
    private level:number;

    constructor(level:number){
        this.level = level;
    }

    public debug(m:any){
        if(this.level<=logLevel.debug){
            console.log(m);
        }
    }
}

const units = {
    ptAtmm:0.35,
    mmAtpt:2.83,
}
export class convertCoord{
    private width:number;
    private height:number;

    constructor(pageSize:{width:number,height:number}){
        this.width = pageSize.width;
        this.height = pageSize.height;
    }
    convertMm2Pt = (mm:number) => {
        return mm*units.mmAtpt;
    }

    convertXY = (mm:{x:number,y:number}) =>{
        const xPt = mm.x*units.mmAtpt;
        const yPt = this.height - (mm.y*units.mmAtpt);
        return {xPt,yPt}
    }
}