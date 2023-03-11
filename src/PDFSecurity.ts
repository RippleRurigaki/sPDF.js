/*
  foliojs/pdfkit https://github.com/foliojs/pdfkit
  Licensed under the MIT license.
    PDFSecurity - represents PDF security settings
    By Yang Liu <hi@zesik.com>

  PDFSecurity.ts Copy from PDF Hopding/pdf-lib PR #1015 by PhakornKiong
    https://github.com/Hopding/pdf-lib/pull/1015
    https://github.com/Hopding/pdf-lib/blob/d067693ad07733c80e873b984f826db64dd3ea65/src/core/security/PDFSecurity.ts

    Modifications : Add Decrypt.
                    Add Support Revesion=6.
                    Add Tool for re-encryption.
                    Fix Type error
  

  getPDFSecurityHashR6()
    Modifications from pdf.js (https://github.com/mozilla/pdf.js/)
    Licensed under the Apache 2.0 open source license.
    The getPDFSecurityHashR6 function contained in this file
    is a modifications to use on 'crypto-js' of the calculatePDF20Hash function in Mozilla's pdf.js project,
*/

import CryptoJS from 'crypto-js';
import saslprep from 'saslprep';
import {PDFDocument as _PDFDocument,PDFDict,PDFObject,PDFName,PDFNumber,PDFContext,PDFArray,PDFHexString, PDFString, PDFBool} from "pdf-lib";
import { buffer2Hex } from './utils';

interface PDFDocument extends _PDFDocument{
  _id:Uint8Array,
}
const PDFDocument = _PDFDocument;

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

interface LiteralObject {
    [name: string]: Literal | PDFObject;
  }
  
type WordArray = CryptoJS.lib.WordArray;
type generateRandomWordArrayFn = (bytes: number) => WordArray;

/**
 * Interface representing type of user permission
 * @interface UserPermission
 */
export interface UserPermission {
  /**
   * Printing Permission
   * For Security handlers of revision <= 2 : Boolean
   * For Security handlers of revision >= 3 : 'lowResolution' or 'highResolution'
   */
  printing?: boolean | 'lowResolution' | 'highResolution';
  /**
   * Modify Content Permission (Other than 'annotating', 'fillingForms' and 'documentAssembly')
   */
  modifying?: boolean;
  /** Copy or otherwise extract text and graphics from document */
  copying?: boolean;
  /** Permission to add or modify text annotations */
  annotating?: boolean;
  /**
   * Security handlers of revision >= 3
   * Fill in existing interactive form fields (including signature fields)
   */
  fillingForms?: boolean;
  /**
   * Security handlers of revision >= 3
   * Extract text and graphics (in support of accessibility to users with disabilities or for other purposes)
   */
  contentAccessibility?: boolean;
  /**
   * Security handlers of revision >= 3
   * Assemble the document (insert, rotate or delete pages and create bookmarks or thumbnail images)
   */
  documentAssembly?: boolean;
}

export type EncryptFn = (buffer: Uint8Array) => Uint8Array;

/**
 * Interface option for security
 * @interface SecurityOption
 */
export interface SecurityOption {
  /**
   * Password that provide unlimited access to the encrypted document.
   *
   * Opening encrypted document with owner password allow full (owner) access to the document
   */
  ownerPassword?: string;

  /** Password that restrict reader according to defined permissions
   *
   * Opening encrypted document with user password will have limitations in accordance to the permission defined.
   */
  userPassword: string;

  /** Object representing type of user permission enforced on the document
   * @link {@link UserPermission}
   */
  permissions?: UserPermission;

  /** Version of PDF, string of '1.x' */
  pdfVersion?: string;
}

interface StdCF {
  AuthEvent: 'DocOpen';
  CFM: 'AESV2' | 'AESV3';
  Length: number;
}

type CF = {
  StdCF: StdCF;
}

type EncDictV = 1 | 2 | 4 | 5;
type EncDictR = 2 | 3 | 4 | 5 | 6;
type EncKeyBits = 40 | 128 | 256;

interface EncDict extends LiteralObject {
  R: EncDictR;
  O: PDFHexString;
  U: PDFHexString;
  P: number;
  V: EncDictV;
  Filter: 'Standard';
}

export interface EncDictV1V2V4 extends EncDict {
  // Only when V > 2
  Length?: number;
  // Only when V === 4
  CF?: CF;
  StmF?: string;
  StrF?: string;
}

export interface EncDictV5 extends EncDict {
  OE: PDFHexString;
  UE: PDFHexString;
  Perms: PDFHexString;
  Length?: number;
  CF: CF;
  StmF: 'StdCF';
  StrF: 'StdCF';
}

/* 
Represent the entire security class for the PDF Document
Output from `_setupEncryption` is the Encryption Dictionary
in compliance to the PDF Specification 
*/
export class PDFSecurity {
  document: PDFDocument;
  version!: EncDictV;
  revesion!: EncDictR;
  dictionary!: EncDictV5 | EncDictV1V2V4;
  keyBits!: EncKeyBits;
  encryptionKey!: WordArray;
  id!: Uint8Array;

  /*   
  ID file is an array of two byte-string constituing 
  a file identifier

  Required if Encrypt entry is present in Trailer
  Doesn't really matter what it is as long as it is 
  consistently used. 
  */
  static generateFileID(info: PDFDict): Uint8Array {
    return wordArrayToBuffer(CryptoJS.MD5(info.toString()));
  }

  static generateRandomWordArray(bytes: number): WordArray {
    return CryptoJS.lib.WordArray.random(bytes);
  }

  static create(
    document: PDFDocument,
    options: SecurityOption = {} as SecurityOption,
  ) {
    return new PDFSecurity(document, options);
  }

  static decrypter(
    encryptionDic:PDFDict,
    context:PDFContext,
    password:string,
    reqPermission?:UserPermission
  ){
    const filter = encryptionDic.get(PDFName.of("Filter"));
    if(!(filter instanceof PDFName) || filter.toString() !== "/Standard"){
        throw new Error(`Unsupport security handler. ${filter?.toString()}`);
    }
    const keylength = encryptionDic.get(PDFName.of("Length"));
    if(!(keylength instanceof PDFNumber)){
        throw new Error (`Unsupport Key length`)
    }
    const version = encryptionDic.get(PDFName.of("V"));
    if(!(version instanceof PDFNumber) || version.asNumber() <=0 || version.asNumber() === 3 || version.asNumber() > 6){
        throw new Error (`Unsupport encrypt version.`)
    }
    const permission = encryptionDic.get(PDFName.of("P"));
    if(!(permission instanceof PDFNumber)){
        throw new Error(`Permision noentry.`);
    }
    const revision = encryptionDic.get(PDFName.of("R"));
    if(!(revision instanceof PDFNumber) || revision.asNumber() < 2 || revision.asNumber() > 6){
        throw new Error (`Unsupport revesion.`)
    }
    if(!(context.trailerInfo.ID instanceof PDFArray) || !context.trailerInfo.ID.asArray()[0]){
      throw new Error (`DocumentID undefined.`);
    }
    const documentID = context.trailerInfo.ID.asArray()[0];
    if(!(documentID instanceof PDFHexString)){
      throw new Error (`DocumentID undefined.`);
    }
    const ownerPasswordValue = encryptionDic.get(PDFName.of("O"));
    if(!(ownerPasswordValue instanceof PDFHexString) && !(ownerPasswordValue instanceof PDFString)){
      throw new Error('O notentry');
    }
    const ownerKey = encryptionDic.get(PDFName.of("OE"));
    if(version.asNumber() === 5 && !(ownerKey instanceof PDFHexString) && !(ownerKey instanceof PDFString)){
      throw new Error('OE notentry');
    }
    const userPasswordValue = encryptionDic.get(PDFName.of("U"));
    if(!(userPasswordValue instanceof PDFHexString) && !(userPasswordValue instanceof PDFString)){
      throw new Error('U notentry');
    }
    const userKey = encryptionDic.get(PDFName.of("UE"));
    if(version.asNumber() === 5 && !(userKey instanceof PDFHexString) && !(userKey instanceof PDFString)){
      throw new Error('OE notentry');
    }
    const perms = encryptionDic.get(PDFName.of("Perms"));
    if(version.asNumber() === 5 && !(perms instanceof PDFHexString) && !(perms instanceof PDFString)){
      throw new Error('OE notentry');
    }
    const encryptMetadataEntry = encryptionDic.get(PDFName.of("EncryptMetadata"));
    const encryptMetadata = (encryptMetadataEntry instanceof PDFBool)
      ?encryptMetadataEntry.asBoolean()
      :true;
    let passwordCheck:"N"|"O"|"U" = "N";
    const ownerPasswordKey = checkOwnerpassword({
      version:version.asNumber(),
      documentID:documentID.asBytes(),
      encryptMetadata:encryptMetadata,
      securityRevision:revision.asNumber() as 2|3|4|5,
      keyLength:keylength.asNumber() as EncKeyBits,
      permissionNo:permission.asNumber(),
      ownerPassword:password||"",
      O:ownerPasswordValue.asBytes(),
      U:userPasswordValue.asBytes(),
      OE:(ownerKey as undefined|PDFString|PDFHexString)?.asBytes(),
      Perms:(perms as undefined|PDFString|PDFHexString)?.asBytes(),
      P:permission.asNumber(),
    });
    if(ownerPasswordKey){
      passwordCheck = "O";
    }
    const userPasswordKey = checkUserpassword({
      version:version.asNumber(),
      documentID:documentID.asBytes(),
      encryptMetadata:encryptMetadata,
      securityRevision:revision.asNumber() as 2|3|4|5,
      keyLength:keylength.asNumber() as EncKeyBits,
      permissionNo:permission.asNumber(),
      userPassword:password||"",
      O:ownerPasswordValue.asBytes(),
      U:userPasswordValue.asBytes(),
      UE:(userKey as undefined|PDFString|PDFHexString)?.asBytes(),
      Perms:(perms as undefined|PDFString|PDFHexString)?.asBytes(),
      P:permission.asNumber(),
    });
    if(passwordCheck !== "O" && userPasswordKey){
      passwordCheck = "U";
    }
    if(ownerPasswordKey && passwordCheck === "O"){
      return {
        decrypt:getDecryptFn(version.asNumber(),ownerPasswordKey,keylength.asNumber()),
        reEncrypt: (obj: number, gen: number)=>{
          return _getEncryptFn(obj,gen,version.asNumber(),keylength.asNumber(),ownerPasswordKey)
        }
      }
    }else if(userPasswordKey && passwordCheck === "U"){
      if(passwordCheck === "U"){
        if(reqPermission){
          const permissionNum = permission.asNumber();
          let reject = false;
          if(reqPermission.printing){
            if(revision.asNumber() <=2){
              if(!(permissionNum & 0x0004)){
                reject = true;
              }
            }else{
              if(reqPermission.printing === "lowResolution" && !(permissionNum & 0x0004)){
                reject = true;
              }
              if(reqPermission.printing === "highResolution" && !(permissionNum & 0x0804)){
                reject = true;
              }
            }
          }
          if(reqPermission.modifying && !(permissionNum & 0x0008)){
            reject = true;
          }
          if(reqPermission.copying && !(permissionNum & 0x0010)){
            reject = true;
          }
          if(reqPermission.annotating && !(permissionNum & 0x0020)){
            reject = true;
          }
          if(reqPermission.fillingForms && !(permissionNum & 0x0040)){
            reject = true;
          }
          if(reqPermission.contentAccessibility && !(permissionNum & 0x0080)){
            reject = true;
          }
          if(reqPermission.documentAssembly && !(permissionNum & 0x0100)){
            reject = true;
          }
          if(!reject){
            return {
              decrypt:getDecryptFn(version.asNumber(),userPasswordKey,keylength.asNumber()),
              reEncrypt:(obj: number, gen: number)=>{
                return _getEncryptFn(obj,gen,version.asNumber(),keylength.asNumber(),userPasswordKey)
              }
            }
          }
        }
      }
    } 
    throw new Error(`Document restriction permission denied.`);
  }

  constructor(
    document: PDFDocument,
    options: SecurityOption = {} as SecurityOption,
  ) {
    if (!options.ownerPassword && !options.userPassword) {
      throw new Error('None of owner password and user password is defined.');
    }

    this.document = document;
    this._setupEncryption(options);
  }

  /* 
  Handle all encryption process and give back 
  EncryptionDictionary that is required
  to be plugged into Trailer of the PDF 
  */
  _setupEncryption(options: SecurityOption) {
    switch (options.pdfVersion) {
      case '1.4':
      case '1.5':
        this.version = 2;
        break;
      case '1.6':
      case '1.7':
        this.version = 4;
        break;
      case '1.7ext3':
        this.version = 5;
        break;
      case '2.0':
        this.version = 5;
        this.revesion = 6;
        break;
      default:
        this.version = 1;
        break;
    }

    switch (this.version) {
      case 1:
      case 2:
      case 4:
        this.dictionary = this._setupEncryptionV1V2V4(this.version, options);
        break;
      case 5:
        if(this.revesion === 6){
          this.dictionary = this._setupEncryptionV5R6(options)
        }else{
          this.dictionary = this._setupEncryptionV5(options);
        }
        break;
    }
  }

  _setupEncryptionV1V2V4(v: EncDictV, options: SecurityOption): EncDictV1V2V4 {
    const encDict = {
      Filter: 'Standard',
    } as EncDictV1V2V4;

    let r: EncDictR;
    let permissions: number;

    switch (v) {
      case 1:
        r = 2;
        this.keyBits = 40;
        permissions = getPermissionsR2(options.permissions);
        break;
      case 2:
        r = 3;
        this.keyBits = 128;
        permissions = getPermissionsR3(options.permissions);
        break;
      case 4:
        r = 4;
        this.keyBits = 128;
        permissions = getPermissionsR3(options.permissions);
        break;
      default:
        throw new Error('Unknown v value');
    }

    const paddedUserPassword: WordArray = processPasswordR2R3R4(
      options.userPassword,
    );
    const paddedOwnerPassword: WordArray = options.ownerPassword
      ? processPasswordR2R3R4(options.ownerPassword)
      : paddedUserPassword;

    const ownerPasswordEntry: WordArray = getOwnerPasswordR2R3R4(
      r,
      this.keyBits,
      paddedUserPassword,
      paddedOwnerPassword,
    );
    this.encryptionKey = getEncryptionKeyR2R3R4(
      r,
      this.keyBits,
      this.document._id,
      paddedUserPassword,
      ownerPasswordEntry,
      permissions,
    );
    let userPasswordEntry;
    if (r === 2) {
      userPasswordEntry = getUserPasswordR2(this.encryptionKey);
    } else {
      userPasswordEntry = getUserPasswordR3R4(
        this.document._id,
        this.encryptionKey,
      );
    }

    encDict.V = v;
    if (v >= 2) {
      encDict.Length = this.keyBits;
    }
    if (v === 4) {
      encDict.CF = {
        StdCF: {
          AuthEvent: 'DocOpen',
          CFM: 'AESV2',
          Length: this.keyBits / 8,
        },
      };
      encDict.StmF = 'StdCF';
      encDict.StrF = 'StdCF';
    }

    encDict.R = r;
    encDict.O = PDFHexString.of(buffer2Hex(wordArrayToBuffer(ownerPasswordEntry)));
    encDict.U = PDFHexString.of(buffer2Hex(wordArrayToBuffer(userPasswordEntry)));
    encDict.P = permissions;
    return encDict;
  }

  _setupEncryptionV5(options: SecurityOption): EncDictV5 {
    const encDict = {
      Filter: 'Standard',
    } as EncDictV5;

    this.keyBits = 256;
    const permissions = getPermissionsR3(options.permissions);

    const processedUserPassword = processPasswordR5R6(options.userPassword);
    const processedOwnerPassword = options.ownerPassword
      ? processPasswordR5R6(options.ownerPassword)
      : processedUserPassword;

    this.encryptionKey = getEncryptionKeyR5R6(
      PDFSecurity.generateRandomWordArray,
    );
    const userPasswordEntry = getUserPasswordR5(
      processedUserPassword,
      PDFSecurity.generateRandomWordArray,
    );
    const userKeySalt = CryptoJS.lib.WordArray.create(
      userPasswordEntry.words.slice(10, 12),
      8,
    );
    const userEncryptionKeyEntry = getUserEncryptionKeyR5(
      processedUserPassword,
      userKeySalt,
      this.encryptionKey,
    );
    const ownerPasswordEntry = getOwnerPasswordR5(
      processedOwnerPassword,
      userPasswordEntry,
      PDFSecurity.generateRandomWordArray,
    );
    const ownerKeySalt = CryptoJS.lib.WordArray.create(
      ownerPasswordEntry.words.slice(10, 12),
      8,
    );
    const ownerEncryptionKeyEntry = getOwnerEncryptionKeyR5(
      processedOwnerPassword,
      ownerKeySalt,
      userPasswordEntry,
      this.encryptionKey,
    );
    const permsEntry = getEncryptedPermissionsR5R6(
      permissions,
      this.encryptionKey,
      PDFSecurity.generateRandomWordArray,
    );

    encDict.V = 5;
    encDict.Length = this.keyBits;
    encDict.CF = {
      StdCF: {
        AuthEvent: 'DocOpen',
        CFM: 'AESV3',
        Length: this.keyBits / 8,
      },
    };
    encDict.StmF = 'StdCF';
    encDict.StrF = 'StdCF';
    encDict.R = 5;
    encDict.O = PDFHexString.of(buffer2Hex(wordArrayToBuffer(ownerPasswordEntry)));
    encDict.OE = PDFHexString.of(buffer2Hex(wordArrayToBuffer(ownerEncryptionKeyEntry)));
    encDict.U = PDFHexString.of(buffer2Hex(wordArrayToBuffer(userPasswordEntry)));
    encDict.UE = PDFHexString.of(buffer2Hex(wordArrayToBuffer(userEncryptionKeyEntry)));
    encDict.P = permissions;
    encDict.Perms = PDFHexString.of(buffer2Hex(wordArrayToBuffer(permsEntry)));
    return encDict;
  }
  _setupEncryptionV5R6(options: SecurityOption): EncDictV5 {
    const encDict = {
      Filter: 'Standard',
    } as EncDictV5;
    this.keyBits = 256;
    const permissions = getPermissionsR3(options.permissions);

    const processedUserPassword = processPasswordR5R6(options.userPassword);
    const processedOwnerPassword = options.ownerPassword
      ? processPasswordR5R6(options.ownerPassword)
      : processedUserPassword;

    this.encryptionKey = getEncryptionKeyR5R6(
      PDFSecurity.generateRandomWordArray,
    );
    const userPasswordEntry = getUserPasswordR6(
      processedUserPassword,
      PDFSecurity.generateRandomWordArray,
    );
    const userKeySalt = CryptoJS.lib.WordArray.create(
      userPasswordEntry.words.slice(10, 12),
      8,
    );
    const userEncryptionKeyEntry = getUserEncryptionKeyR6(
      processedUserPassword,
      userKeySalt,
      this.encryptionKey,
    );
    const ownerPasswordEntry = getOwnerPasswordR6(
      processedOwnerPassword,
      userPasswordEntry,
      PDFSecurity.generateRandomWordArray,
    );
    const ownerKeySalt = CryptoJS.lib.WordArray.create(
      ownerPasswordEntry.words.slice(10, 12),
      8,
    );
    const ownerEncryptionKeyEntry = getOwnerEncryptionKeyR6(
      processedOwnerPassword,
      ownerKeySalt,
      userPasswordEntry,
      this.encryptionKey,
    );
    const permsEntry = getEncryptedPermissionsR5R6(
      permissions,
      this.encryptionKey,
      PDFSecurity.generateRandomWordArray,
    );
    encDict.V = 5;
    encDict.Length = this.keyBits;
    encDict.CF = {
      StdCF: {
        AuthEvent: 'DocOpen',
        CFM: 'AESV3',
        Length: this.keyBits / 8,
      },
    };
    encDict.StmF = 'StdCF';
    encDict.StrF = 'StdCF';
    encDict.R = 6;
    encDict.O = PDFHexString.of(buffer2Hex(wordArrayToBuffer(ownerPasswordEntry)));
    encDict.OE = PDFHexString.of(buffer2Hex(wordArrayToBuffer(ownerEncryptionKeyEntry)));
    encDict.U = PDFHexString.of(buffer2Hex(wordArrayToBuffer(userPasswordEntry)));
    encDict.UE = PDFHexString.of(buffer2Hex(wordArrayToBuffer(userEncryptionKeyEntry)));
    encDict.P = permissions;
    encDict.Perms = PDFHexString.of(buffer2Hex(wordArrayToBuffer(permsEntry)));
    return encDict;
  }

  getEncryptFn(obj: number, gen: number) {
    return _getEncryptFn(obj,gen,this.version,this.keyBits,this.encryptionKey);
  }
}

/**
 * Get Permission Flag for use Encryption Dictionary (Key: P)
 * For Security Handler revision 2
 *
 * Only bit position 3,4,5,6,9,10,11 and 12 is meaningful
 * Refer Table 22 - User access permission
 * @param  {permissionObject} {@link UserPermission}
 * @returns number - Representing unsigned 32-bit integer
 */
const getPermissionsR2 = (permissionObject: UserPermission = {}) => {
  let permissions = 0xffffffc0 >> 0;
  if (permissionObject.printing) {
    permissions |= 0b000000000100;
  }
  if (permissionObject.modifying) {
    permissions |= 0b000000001000;
  }
  if (permissionObject.copying) {
    permissions |= 0b000000010000;
  }
  if (permissionObject.annotating) {
    permissions |= 0b000000100000;
  }
  return permissions;
};

/**
 * Get Permission Flag for use Encryption Dictionary (Key: P)
 * For Security Handler revision 2
 *
 * Only bit position 3,4,5,6,9,10,11 and 12 is meaningful
 * Refer Table 22 - User access permission
 * @param  {permissionObject} {@link UserPermission}
 * @returns number - Representing unsigned 32-bit integer
 */
const getPermissionsR3 = (permissionObject: UserPermission = {}) => {
  let permissions = 0xfffff0c0 >> 0;
  if (
    permissionObject.printing === 'lowResolution' ||
    permissionObject.printing
  ) {
    permissions |= 0b000000000100;
  }
  if (permissionObject.printing === 'highResolution') {
    permissions |= 0b100000000100;
  }
  if (permissionObject.modifying) {
    permissions |= 0b000000001000;
  }
  if (permissionObject.copying) {
    permissions |= 0b000000010000;
  }
  if (permissionObject.annotating) {
    permissions |= 0b000000100000;
  }
  if (permissionObject.fillingForms) {
    permissions |= 0b000100000000;
  }
  if (permissionObject.contentAccessibility) {
    permissions |= 0b001000000000;
  }
  if (permissionObject.documentAssembly) {
    permissions |= 0b010000000000;
  }
  return permissions;
};

const getUserPasswordR2 = (encryptionKey: CryptoJS.lib.WordArray) =>
  CryptoJS.RC4.encrypt(processPasswordR2R3R4(), encryptionKey).ciphertext;

const getUserPasswordR3R4 = (
  documentId: Uint8Array,
  encryptionKey: WordArray,
) => {
  const key = encryptionKey.clone();
  let cipher = CryptoJS.MD5(
    processPasswordR2R3R4().concat(
      CryptoJS.lib.WordArray.create((documentId as unknown) as number[]),
    ),
  );
  for (let i = 0; i < 20; i++) {
    const xorRound = Math.ceil(key.sigBytes / 4);
    for (let j = 0; j < xorRound; j++) {
      key.words[j] =
        encryptionKey.words[j] ^ (i | (i << 8) | (i << 16) | (i << 24));
    }
    cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext;
  }
  return cipher.concat(
    CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),
  );
};

const getOwnerPasswordR2R3R4 = (
  r: EncDictR,
  keyBits: EncKeyBits,
  paddedUserPassword: WordArray,
  paddedOwnerPassword: WordArray,
): CryptoJS.lib.WordArray => {
  let digest = paddedOwnerPassword;
  let round = r >= 3 ? 51 : 1;
  for (let i = 0; i < round; i++) {
    digest = CryptoJS.MD5(digest);
  }

  const key = digest.clone();
  key.sigBytes = keyBits / 8;
  let cipher = paddedUserPassword;
  round = r >= 3 ? 20 : 1;
  for (let i = 0; i < round; i++) {
    const xorRound = Math.ceil(key.sigBytes / 4);
    for (let j = 0; j < xorRound; j++) {
      key.words[j] = digest.words[j] ^ (i | (i << 8) | (i << 16) | (i << 24));
    }
    cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext;
  }
  return cipher;
};
const decryptOpram = (
  r: EncDictR,
  keyBits: EncKeyBits,
  O: WordArray,
  paddedOwnerPassword: WordArray,
) => {
  let digest = paddedOwnerPassword;
  let round = r >= 3 ? 51 : 1;
  for (let i = 0; i < round; i++) {
    digest = CryptoJS.MD5(digest);
  }
  const key = digest.clone();
  key.sigBytes = keyBits / 8;
  let cipher = O;
  round = r >= 3 ? 20 : 1;
  for (let i = 0; i < round; i++) {
    const xorRound = Math.ceil(key.sigBytes / 4);
    for (let j = 0; j < xorRound; j++) {
      key.words[j] = digest.words[j] ^ (i | (i << 8) | (i << 16) | (i << 24));
    }
    const pram = CryptoJS.lib.CipherParams.create({
      ciphertext:cipher,
      });
    cipher = CryptoJS.RC4.decrypt(pram,key);
  }
  return cipher;

}
const getEncryptionKeyR2R3R4 = (
  r: EncDictR,
  keyBits: EncKeyBits,
  documentId: Uint8Array,
  paddedUserPassword: WordArray,
  ownerPasswordEntry: WordArray,
  permissions: number,
  encryptMetadata:boolean = true,
): WordArray => {
  let key = paddedUserPassword
    .clone()
    .concat(ownerPasswordEntry)
    .concat(CryptoJS.lib.WordArray.create([lsbFirstWord(permissions)], 4))
    .concat(CryptoJS.lib.WordArray.create((documentId as unknown) as number[]));
  if(r===4 && !encryptMetadata){
    key.concat(CryptoJS.lib.WordArray.create([0xFFFFFFFF]));
  }
  const round = r >= 3 ? 51 : 1;
  for (let i = 0; i < round; i++) {
    key = CryptoJS.MD5(key);
    key.sigBytes = keyBits / 8;
  }
  return key;
};

const getUserPasswordR5 = (
  processedUserPassword: WordArray,
  generateRandomWordArray: generateRandomWordArrayFn,
) => {
  const validationSalt = generateRandomWordArray(8);
  const keySalt = generateRandomWordArray(8);
  return CryptoJS.SHA256(processedUserPassword.clone().concat(validationSalt))
    .concat(validationSalt)
    .concat(keySalt);
};
const getUserPasswordR6= (
  processedUserPassword: WordArray,
  generateRandomWordArray: generateRandomWordArrayFn,
) => {
  const validationSalt = generateRandomWordArray(8);
  const keySalt = generateRandomWordArray(8);
  return getPDFSecurityHashR6(
    processedUserPassword
    ,processedUserPassword.clone().concat(validationSalt)
    ,CryptoJS.lib.WordArray.create())
    .concat(validationSalt)
    .concat(keySalt);
};
const getUserEncryptionKeyR5 = (
  processedUserPassword: WordArray,
  userKeySalt: WordArray,
  encryptionKey: WordArray,
) => {
  const key = CryptoJS.SHA256(
    processedUserPassword.clone().concat(userKeySalt),
  );
  const options = {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
    iv: CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),
  };
  return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext;
};
const getUserEncryptionKeyR6= (
  processedUserPassword: WordArray,
  userKeySalt: WordArray,
  encryptionKey: WordArray,
) => {
  const key = getPDFSecurityHashR6(
    processedUserPassword
    ,processedUserPassword.clone().concat(userKeySalt)
    ,CryptoJS.lib.WordArray.create());
  const options = {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
    iv: CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),
  };
  return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext;
};
const getOwnerPasswordR5 = (
  processedOwnerPassword: WordArray,
  userPasswordEntry: WordArray,
  generateRandomWordArray: generateRandomWordArrayFn,
) => {
  const validationSalt = generateRandomWordArray(8);
  const keySalt = generateRandomWordArray(8);
  return CryptoJS.SHA256(
    processedOwnerPassword
      .clone()
      .concat(validationSalt)
      .concat(userPasswordEntry),
  )
    .concat(validationSalt)
    .concat(keySalt);
};
const getOwnerPasswordR6 = (
  processedOwnerPassword: WordArray,
  userPasswordEntry: WordArray,
  generateRandomWordArray: generateRandomWordArrayFn,
) => {
  const validationSalt = generateRandomWordArray(8);
  const keySalt = generateRandomWordArray(8);
  return getPDFSecurityHashR6(
    processedOwnerPassword
    ,processedOwnerPassword.clone().concat(validationSalt).concat(userPasswordEntry)
    ,userPasswordEntry)
  .concat(validationSalt)
  .concat(keySalt);
};
const getOwnerEncryptionKeyR5 = (
  processedOwnerPassword: WordArray,
  ownerKeySalt: WordArray,
  userPasswordEntry: WordArray,
  encryptionKey: WordArray,
) => {
  const key = CryptoJS.SHA256(
    processedOwnerPassword
      .clone()
      .concat(ownerKeySalt)
      .concat(userPasswordEntry),
  );
  const options = {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
    iv: CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),
  };
  return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext;
};
const getOwnerEncryptionKeyR6 = (
  processedOwnerPassword: WordArray,
  ownerKeySalt: WordArray,
  userPasswordEntry: WordArray,
  encryptionKey: WordArray,
) => {
  const key = getPDFSecurityHashR6(
    processedOwnerPassword
    ,processedOwnerPassword.clone().concat(ownerKeySalt).concat(userPasswordEntry)
    ,userPasswordEntry);
  const options = {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
    iv: CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),
  };
  return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext;
};
const getEncryptionKeyR5R6 = (
  generateRandomWordArray: generateRandomWordArrayFn,
) => generateRandomWordArray(32);

const getEncryptedPermissionsR5R6 = (
  permissions: number,
  encryptionKey: WordArray,
  generateRandomWordArray: generateRandomWordArrayFn,
) => {
  const cipher = CryptoJS.lib.WordArray.create(
    [lsbFirstWord(permissions), 0xffffffff, 0x54616462],
    12,
  ).concat(generateRandomWordArray(4));
  const options = {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.NoPadding,
  };
  return CryptoJS.AES.encrypt(cipher, encryptionKey, options).ciphertext;
};

const processPasswordR2R3R4 = (password = '') => {
  const out = new Uint8Array(32);
  const length = password.length;
  let index = 0;
  while (index < length && index < 32) {
    const code = password.charCodeAt(index);
    if (code > 0xff) {
      throw new Error('Password contains one or more invalid characters.');
    }
    out[index] = code;
    index++;
  }
  while (index < 32) {
    out[index] = PASSWORD_PADDING[index - length];
    index++;
  }
  return CryptoJS.lib.WordArray.create((out as unknown) as number[]);
};

const processPasswordR5R6 = (password = '') => {
  password = decodeURI(encodeURIComponent(saslprep(password)));
  const length = Math.min(127, password.length);
  const out = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    out[i] = password.charCodeAt(i);
  }

  return CryptoJS.lib.WordArray.create((out as unknown) as number[]);
};



const lsbFirstWord = (data: number): number =>
  ((data & 0xff) << 24) |
  ((data & 0xff00) << 8) |
  ((data >> 8) & 0xff00) |
  ((data >> 24) & 0xff);

const wordArrayToBuffer = (wordArray: WordArray): Uint8Array => {
  const byteArray = [];
  for (let i = 0; i < wordArray.sigBytes; i++) {
    byteArray.push(
      (wordArray.words[Math.floor(i / 4)] >> (8 * (3 - (i % 4)))) & 0xff,
    );
  }

  return Uint8Array.from(byteArray);
};

const checkUserpassword = (pram:{
  version:number,
  securityRevision:2|3|4|5|6,
  keyLength:EncKeyBits,
  userPassword:string,
  permissionNo:number,
  documentID:Uint8Array,
  encryptMetadata:boolean,
  O:Uint8Array,
  U:Uint8Array,
  UE?:Uint8Array,
  Perms?:Uint8Array,
  P:number,
})=>{
  if(pram.version <= 4){
    if(pram.securityRevision ===2||pram.securityRevision === 3||pram.securityRevision === 4){
      const paddedUserPassword: WordArray = processPasswordR2R3R4(
        pram.userPassword,
      );
      const userAuth = userPasswordAuthV4({
        securityRevision:pram.securityRevision,
        keyLength:pram.keyLength,
        paddedUserPassword:paddedUserPassword,
        permissionNo:pram.permissionNo,
        documentID:pram.documentID,
        encryptMetadata:pram.encryptMetadata,
        O:pram.O,
      });
      if(pram.U.subarray(0,16).toString() === userAuth.U.subarray(0,16).toString()){
        return userAuth.key;
      }
      return;
    }
  }else if(pram.version === 5){
    if((pram.securityRevision === 5 || pram.securityRevision === 6) && pram.UE && pram.Perms){
      const UValid = CryptoJS.lib.WordArray.create(pram.U.subarray(0,32) as unknown as number[]);
      const UEWord = CryptoJS.lib.WordArray.create(pram.UE as unknown as number[]);
      const PermsWord = CryptoJS.lib.WordArray.create(pram.Perms as unknown as number[]);
      const userValidationSalt = CryptoJS.lib.WordArray.create(pram.U.subarray(32,32+8) as unknown as number[]);
      const userKeySalt = CryptoJS.lib.WordArray.create(pram.U.subarray(32+8,32+8+8) as unknown as number[]);
      const processedPassword =  processPasswordR5R6(pram.userPassword);
      const saltingValidPassword = processedPassword.clone().concat(userValidationSalt);
      const validhash = pram.securityRevision === 5
        ? CryptoJS.SHA256(saltingValidPassword)
        :getPDFSecurityHashR6(
          processedPassword
          ,processedPassword.clone().concat(userValidationSalt)
          ,CryptoJS.lib.WordArray.create());
      if(validhash.toString() !== UValid.toString()){
        // passwotd is not userpassword
        return false;
      }
      const intermediateUserKey = pram.securityRevision === 5
        ?CryptoJS.SHA256(processedPassword.clone().concat(userKeySalt))
        :getPDFSecurityHashR6(
          processedPassword
          ,processedPassword.clone().concat(userKeySalt)
          ,CryptoJS.lib.WordArray.create());
      const fileEncryptionKey = CryptoJS.AES.decrypt(
        CryptoJS.lib.CipherParams.create({ciphertext:UEWord})
        ,intermediateUserKey
        ,{"iv":CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),padding: CryptoJS.pad.NoPadding,mode:CryptoJS.mode.CBC}
      );
      const decPerms = wordArrayToBuffer(CryptoJS.AES.decrypt(
        CryptoJS.lib.CipherParams.create({ciphertext:PermsWord})
        ,fileEncryptionKey
        ,{"iv":CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),padding: CryptoJS.pad.NoPadding,mode:CryptoJS.mode.ECB})
      );
      const adb = Array.from("adb").map(v=>v.charCodeAt(0));
      if(decPerms[9] !== adb[0] || decPerms[10] !== adb[1] || decPerms[11] !== adb[2]){
        //"Perms decrypt error"
        return false;
      }
      const permission = (decPerms[3] << 24) + (decPerms[2] << 16) + (decPerms[1] << 8) + decPerms[0];
      if(permission !== pram.P){
        //"Perms decrypt error"
        return false;
      }
      return fileEncryptionKey;
    }
  }
}
const userPasswordAuthV4 = (pram:{
  securityRevision:2|3|4|5,
  keyLength:EncKeyBits,
  paddedUserPassword:WordArray,
  permissionNo:number,
  documentID:Uint8Array,
  encryptMetadata:boolean,
  O:Uint8Array,
}) => {
  const encryptionKey: WordArray = getEncryptionKeyR2R3R4(
    pram.securityRevision,
    pram.keyLength,
    pram.documentID,
    pram.paddedUserPassword,
    CryptoJS.lib.WordArray.create((pram.O as unknown) as number[]),
    pram.permissionNo,
    pram.securityRevision===4?pram.encryptMetadata:true,
  );
  let userPasswordEntry: WordArray;
  if (pram.securityRevision === 2) {
    userPasswordEntry = getUserPasswordR2(encryptionKey);
  } else {
    userPasswordEntry = getUserPasswordR3R4(
      pram.documentID,
      encryptionKey,
    );
  }
  return {U:wordArrayToBuffer(userPasswordEntry),key:encryptionKey};
}

const checkOwnerpassword = (pram:{
  version:number,
  securityRevision:2|3|4|5|6,
  keyLength:EncKeyBits,
  ownerPassword:string,
  permissionNo:number,
  documentID:Uint8Array,
  encryptMetadata:boolean,
  O:Uint8Array,
  OE?:Uint8Array,
  U:Uint8Array,
  Perms?:Uint8Array,
  P:number,
})=>{
  if(pram.version <= 4){
    if(pram.securityRevision ===2||pram.securityRevision === 3||pram.securityRevision === 4){
      const paddedOwnerPassword: WordArray = processPasswordR2R3R4(pram.ownerPassword)
      const decryptedUserpassword: WordArray = decryptOpram(pram.securityRevision,pram.keyLength,CryptoJS.lib.WordArray.create((pram.O as unknown) as number[]),paddedOwnerPassword);
      const userAuth = userPasswordAuthV4({
        securityRevision:pram.securityRevision,
        keyLength:pram.keyLength,
        paddedUserPassword:decryptedUserpassword,
        permissionNo:pram.permissionNo,
        documentID:pram.documentID,
        encryptMetadata:pram.encryptMetadata,
        O:pram.O,
      });
      if(pram.U.subarray(0,16).toString() === userAuth.U.subarray(0,16).toString()){
        return userAuth.key;
      }
      return;
    }
  }else if(pram.version === 5){
    if((pram.securityRevision===5 || pram.securityRevision === 6) &&pram.OE){
      const Uword = CryptoJS.lib.WordArray.create(pram.U as unknown as number[]);
      const OEWord = CryptoJS.lib.WordArray.create(pram.OE as unknown as number[]);
      const validO = CryptoJS.lib.WordArray.create(pram.O.subarray(0,32) as unknown as number[]);
      const PermsWord = CryptoJS.lib.WordArray.create(pram.Perms as unknown as number[]);
      const ownerValidationSalt = CryptoJS.lib.WordArray.create(pram.O.subarray(32,32+8) as unknown as number[]);
      const ownerKeySalt = CryptoJS.lib.WordArray.create(pram.O.subarray(32+8,32+8+8) as unknown as number[]);
      const processedPassword = processPasswordR5R6(pram.ownerPassword);
      const validHash = pram.securityRevision === 5
        ?CryptoJS.SHA256(processedPassword.clone().concat(ownerValidationSalt).concat(Uword))
        :getPDFSecurityHashR6(
          processedPassword
          ,processedPassword.clone().concat(ownerValidationSalt).concat(Uword)
          ,Uword);
      if(validHash.toString() !== validO.toString()){
        //not ownerpassword;
        return false;
      }
      const intermediateOwnerKey = pram.securityRevision === 5
        ?CryptoJS.SHA256(processedPassword.clone().concat(ownerKeySalt).concat(Uword))
        :getPDFSecurityHashR6(
          processedPassword
          ,processedPassword.clone().concat(ownerKeySalt).concat(Uword)
          ,Uword);
      const fileEncryptionKey = CryptoJS.AES.decrypt(
        CryptoJS.lib.CipherParams.create({ciphertext:OEWord})
        ,intermediateOwnerKey
        ,{"iv":CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),padding: CryptoJS.pad.NoPadding,mode:CryptoJS.mode.CBC}
      );
      const decPerms = wordArrayToBuffer(CryptoJS.AES.decrypt(
        CryptoJS.lib.CipherParams.create({ciphertext:PermsWord})
        ,fileEncryptionKey
        ,{"iv":CryptoJS.lib.WordArray.create((null as unknown) as undefined, 16),padding: CryptoJS.pad.NoPadding,mode:CryptoJS.mode.ECB})
      );
      const adb = Array.from("adb").map(v=>v.charCodeAt(0));
      if(decPerms[9] !== adb[0] || decPerms[10] !== adb[1] || decPerms[11] !== adb[2]){
        //Perms decrypt error
        return false;
      }
      const permission = (decPerms[3] << 24) + (decPerms[2] << 16) + (decPerms[1] << 8) + decPerms[0];
      if(permission !== pram.P){
        //Perms decrypt error
        return false;
      }
      //throw 0;
      return fileEncryptionKey;
    }
  }
}
const getDecryptFn = (version:number,encryptionKey:WordArray,keyBits:number)=>{
  return (encData:Uint8Array,objectNumber:number,generetionNumber:number)=>{
    const obj = objectNumber;
    const gen = generetionNumber;
    let digest: WordArray;
    let key: WordArray = CryptoJS.lib.WordArray.create();
    if (version < 5) {
      digest = encryptionKey
        .clone()
        .concat(
          CryptoJS.lib.WordArray.create(
            [
              ((obj & 0xff) << 24) |
                ((obj & 0xff00) << 8) |
                ((obj >> 8) & 0xff00) |
                (gen & 0xff),
              (gen & 0xff00) << 16,
            ],
            5,
          ),
        );

      if (version === 1 || version === 2) {
        key = CryptoJS.MD5(digest);
        key.sigBytes = Math.min(16, keyBits / 8 + 5);
        const pram = CryptoJS.lib.CipherParams.create({
          ciphertext:CryptoJS.lib.WordArray.create((encData as unknown) as number[]),
        });
        return wordArrayToBuffer(CryptoJS.RC4.decrypt(pram,key))
      }

      if (version === 4) {
        key = CryptoJS.MD5(
          digest.concat(CryptoJS.lib.WordArray.create([0x73416c54], 4)),
        );
      }
    } else if (version === 5) {
      key = encryptionKey;
    } else {
      throw new Error('Unknown V value');
    }
    const pram = CryptoJS.lib.CipherParams.create({
      ciphertext:CryptoJS.lib.WordArray.create(encData.subarray(16) as unknown as number[]),
    });
    const X = CryptoJS.AES.decrypt(pram,key,{"iv":CryptoJS.lib.WordArray.create(encData.subarray(0,16) as unknown as number[])});
    return wordArrayToBuffer(X);
  }
}
const _getEncryptFn = (obj: number, gen: number,version:number,keyBits:number,encryptionKey:WordArray) =>{
  let digest: WordArray;
  let key: WordArray;
  if (version < 5) {
    digest = encryptionKey
      .clone()
      .concat(
        CryptoJS.lib.WordArray.create(
          [
            ((obj & 0xff) << 24) |
              ((obj & 0xff00) << 8) |
              ((obj >> 8) & 0xff00) |
              (gen & 0xff),
            (gen & 0xff00) << 16,
          ],
          5,
        ),
      );

    if (version === 1 || version === 2) {
      key = CryptoJS.MD5(digest);
      key.sigBytes = Math.min(16, keyBits / 8 + 5);
      return (buffer: Uint8Array) =>
        wordArrayToBuffer(
          CryptoJS.RC4.encrypt(
            CryptoJS.lib.WordArray.create((buffer as unknown) as number[]),
            key,
          ).ciphertext,
        );
    }

    if (version === 4) {
      key = CryptoJS.MD5(
        digest.concat(CryptoJS.lib.WordArray.create([0x73416c54], 4)),
      );
    }
  } else if (version === 5) {
    key = encryptionKey;
  } else {
    throw new Error('Unknown V value');
  }

  const iv = PDFSecurity.generateRandomWordArray(16);
  const options = {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
    iv,
  };

  return (buffer: Uint8Array) =>
    wordArrayToBuffer(
      iv
        .clone()
        .concat(
          CryptoJS.AES.encrypt(
            CryptoJS.lib.WordArray.create((buffer as unknown) as number[]),
            key,
            options,
          ).ciphertext,
        ),
    );
}

const getPDFSecurityHashR6 = (
  processedPassword : WordArray,
  salt:WordArray,
  U:WordArray,
)=>{
  let hash = CryptoJS.SHA256(salt);
  let intermediateKey = CryptoJS.lib.WordArray.create();

  let idx = 0;
  while(idx < 64 || wordArrayToBuffer(intermediateKey)[intermediateKey.sigBytes-1] > idx - 32){
    const comb = processedPassword.clone().concat(hash).concat(U);
    const intermediateKey2 = CryptoJS.lib.WordArray.create();
    for(let idy=0;idy<64;idy++){
      intermediateKey2.concat(comb)
    }
    intermediateKey = CryptoJS.AES.encrypt(
      intermediateKey2,
      CryptoJS.lib.WordArray.create(hash.words.slice(0,4)),
      {iv:CryptoJS.lib.WordArray.create(hash.words.slice(4,8)),padding: CryptoJS.pad.NoPadding,mode:CryptoJS.mode.CBC}
      ).ciphertext;
    const r16 = intermediateKey.clone();
    r16.sigBytes = 16;
    r16.clamp();
    // r16 % 3 = ???
    // !! Unable 128bit modulo on JavaScript.
    // Equivalence:
    // :(A+B) % 3 = ((A % 3) + (B % 3)) % 3
    // :(A*B) % 3 = ((A % 3) * (B % 3)) % 3
    //
    //  (2**8) % 3 = 1 ,  (2**8)*(2**8) % 3 = ((2**8) % 3 * (2**8) %3 ) % 3 = (1*1) % 3 = 1 % 3 = 1 
    // :(2**(8*n)) % 3 = 1
    // :(A * 2**(8*n)) % 3 = (A % 3 * 1 % 3) = (A %3 * 1) % 3 = (A % 3) % 3 = A % 3
    // r16 % 3 = ((r16[0] * 2**(8*15)) % 3 + (r16[1] * 2**(8*14)) %3 + (r16[2] * 2**(8*13)) % 3 + ... + (r16[15] *2**(8*0))) % 3
    //         = ((r16[0] % 3) * (2**(8*15)) % 3) % 3) % 3 + ...
    //         = ((r16[0] % 3) * 1 % 3) % 3 + ...
    //         = ((r16[0] % 3) % 3) % 3 + ...
    //         = r16[0] % 3 + r16[1] % 3 + r16[2] % 3 + ... + r16[15] % 3
    //         = (r16[0] + r16[1] + r16[2] + ... + r16[15]) % 3
    // 255*16 < Number.MAX_SAFE_INTEGER. 
    // OK, That is, every byte is added, to get modulo 3.
    const remainder = (wordArrayToBuffer(r16).reduce((a,b)=>a+b,0)) % 3;
    if(remainder === 0){
      hash = CryptoJS.SHA256(intermediateKey);
    }else if(remainder === 1){
      hash = CryptoJS.SHA384(intermediateKey);
    }else{
      hash = CryptoJS.SHA512(intermediateKey);
    }
    idx++;
  }
  hash.sigBytes = 32;
  hash.clamp();
  return hash;
}
/* 
  7.6.3.3 Encryption Key Algorithm
  Algorithm 2
  Password Padding to pad or truncate
  the password to exactly 32 bytes
*/
const PASSWORD_PADDING = [
  0x28,
  0xbf,
  0x4e,
  0x5e,
  0x4e,
  0x75,
  0x8a,
  0x41,
  0x64,
  0x00,
  0x4e,
  0x56,
  0xff,
  0xfa,
  0x01,
  0x08,
  0x2e,
  0x2e,
  0x00,
  0xb6,
  0xd0,
  0x68,
  0x3e,
  0x80,
  0x2f,
  0x0c,
  0xa9,
  0xfe,
  0x64,
  0x53,
  0x69,
  0x7a,
];

export default PDFSecurity;