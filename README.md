# is ?

Digital signatures of PDF and Encrypt/Decrypt PDF, on JavaScript.

# Notice

This library override pdf-lib some functions.<br>
Maybe comatible with original ,but not limited to the warranties.<br>
Using "@ts-ignore" to access pdf-lib private properties | functions, which may not fit your policy.<br>
Not adequately tested,"NOT LIMITED TO THE WARRANTIES"<br>

# Thanks

The issue post at [pdf-lib](https://github.com/cantoo-scribe/pdf-lib) on how to sign was helpful.<br>
[PR#1015](https://github.com/Hopding/pdf-lib/pull/1015) on pdf-lib about encryption was helpful.<br>

# Usage

## pdfSigner Class<br>

``` ts
import {pdfSigner} from "spdf";
const signer = new pdfSigner();
```

### Member
- [New Sign](#newsing)<br>
- [Add Sign](#add-sign)<br>
- [Add TimeStamp](#add-timestamp)<br>
- [Add DSS](#add-dss)<br>
- [ADD LastTimeStamp-DSS](#add-lasttimestamp-dss)<br>

## Global

``` ts
import {decryptPDF, encryptPDF} from "spdf";
```

### Member
- [encryptPDF](#encryptpdf)<br>
- [decryptPDF](#decryptpdf)<br>

---

## newSign
* Create a signed PDF.

``` ts
pdfSigner.newSing: (pdf:string | Uint8Array | ArrayBuffer, certs: CERTIFICATEs, options?: newSignOptions) => Promise<Uint8Array>
```
## CERTIFICATEs

| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| signer.cert | string\|Uint8Array | Requested | X509 PEM or DER |
| signer.key | string\|Uint8Array | Requested | RSA,DSA,ECDSA private key PKCS#5,#8 PEM or DER |
| signer.keyPass | string | Option | If key is encrypted,set this. |
| caCerts | Array<string\|Uint8Array> | Optional | If embedded CA certificates in signature, set this. |

> Import Certificate and Key is dependency on [jsrsasign](https://kjur.github.io/jsrsasign/),Support format look jsrsasign [reference](https://kjur.github.io/jsrsasign/api/).

---

### newSignOptions
| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| openPassword | string | If pdf is encrypted<br>Requested | **OwnerPassword** required |
| hashAlg | 'sha1'<br>'sha256'<br>'sha384'<br>'sha512' | Option<br>DEFAULT:'sha256' | Sign hash algorithm. |
| encrypt | [EncryptOptions](#encryptoptions) | Optional | If request PDF output encrypt,set this. |
| signer | [SignerOptions](#signeroptions) | Optional | Set of the signing. |
| signature | [signature](#signature) | Optional | Visible signature. |
| embeddedTimeStamp | [TSASarver](#tsasarver) | Optional | If request embedded TimeStamp in signature, set this. |
| DocMDP | 1\|2\|3 | Optional | The access permissions granted for document.|
> The value of DocMDP is quoted to the ISO-32000-1.<br>
1.No changes to the document shall be permitted; any change to the document shall invalidate the signature.<br>2.Permitted changes shall be filling in forms, instantiating page templates, and signing; other changes shall invalidate the signature.<br>3.Permitted changes shall be the same as for 2, as well as annotation creation, deletion, and modification; other changes shall invalidate the signature.

---

### EncryptOptions

[see](#encryptoptions-1)

---

### SignerOptions

| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| Name | string | Optional | The name of the person or authority signing the document. |
| Location | string | Optional | The CPU host name or physical location of the signing. |
| Reason | string | Optional | The reason for the signing. |
| ContactInfo | string | Optional | Information provided by the signer to enable a recipient to contact the signer to verify the signature. |

---

### signature<br>
Visible signature.

| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| page | number | Requested | one-based,0 is invalid. |
| rect | [RECT](#rect) | Requested | Signature area-rect. |
| text | [SignText](#signtext) | Optional | Visible text. |
| image | Uint8Array | Optional | JPEG or PNG visible image. |
| reverseImgTxt | boolean | Optional<br>DEFAULT:false | false:Text above image<br>true:Image above text. |

---

### RECT

| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| x | number | Requested | Distance left mm |
| y | number | Requested | Distance top mm |
| w | number | Requested | Width mm |
| w | number | Requested | Height mm |

---

### SignText

| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| txt | string | Requested | Visible text. |
| size | number | Optional<br>DEFAULT:10 | Text size. |
| x | number | Optional<br>DEFAULT:0 | Distance signatureRect-Left. |
| y | number | Optional<br>DEFAULT:0 | Distance signatureRect-Bouttom. |
| fontdata | Uint8Array | Optional<br>DEFAULT:Courier | Text font data. |

---

### TSASarver

| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| url | string | Requested | TSA Sarver URL |
| hashAlg | 'sha1'<br>'sha256'<br>'sha384'<br>'sha512' | Optional<br>DEFAULT:'sha256' | TimeStamp hash algorithm. |
| certSize | number | Optional<br>DEFAULT:6144 | Size to be allocated for Timestamp certificate |

Not available in web browsers due to CORS.
- Allocate Size<br>
PDF signatures must be pre-allocated space.<br>
The size of the space is estimated from the certificate and allocated,<br>
but the timestamp cannot check the size of the certificate in advance.<br>
If there is not enough space, the timestamp will be set to a sufficient size based on the results obtained once,<br>
but it will need to be signed again.<br>
In other words, if there is not enough space, the timestamping will be requested twice.<br>
If the area is large enough, it cannot be reduced.

---

## Add sign
* Add(inculumental) a signature.<br>
Add a new signature without modifying the PDF document.<br>
Existing content, including signatures, will be maintained.<br>
If encrypted,encryption is maintained.<br>

``` ts
pdfSigner.pdfSigner.inculumentalSign: (pdf:string | Uint8Array | ArrayBuffer, certs: CERTIFICATEs, options?: inclumentalSignOptions) => Promise<Uint8Array>
```

## CERTIFICATEs
[See](#certificates)

---

## inclumentalSignOptions
| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| openPassword | string | If pdf is encrypted<br>Requested | If userpassword,allowed create signature fields. |
| hashAlg | 'sha1'<br>'sha256'<br>'sha384'<br>'sha512' | Option<br>DEFAULT:'sha256' | Sign hash algorithm. |
| signer | [SignerOptions](#signeroptions) | Optional | Set of the signing. |
| signature | [signature](#signature) | Optional | Visible signature. |
| embeddedTimeStamp | [TSASarver](#tsasarver) | Optional | If request embedded TimeStamp in signature, set this. |


---


## Add TimeStamp
* Add(inculumental) a Timestamp.<br>
Add a new timestamp without modifying the PDF document.<br>
Existing content, including signatures, will be maintained.<br>
If encrypted,encryption is maintained.<br>

``` TS
pdfSigner.inculumentalTimeStamp: (pdf:string | Uint8Array | ArrayBuffer, tsaPram: timeStampOptions) => Promise<Uint8Array>
```

### timeStampOptions
| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| TSA | [TSASarver](#tsasarver) | Requested |  |
| openPassword | string | If pdf is encrypted<br>Requested | If userpassword,allowed create signature fields. |

---


## Add DSS
* Add(inculumental) a DSS.<br>
Embeds the verification information of the currently embedded certificate.<br>
Add a DSS without modifying the PDF document.<br>
Existing content, including signatures, will be maintained.<br>
If encrypted,encryption is maintained.<br>
Simply, it enables LTV.<br>
Processes all signatures, if you have already embedded the DSS, you will need to embed the DSS for the added timestamp only.<br>
See [ADD LastTimeStamp-DSS](#add-lasttimestamp-dss)

``` TS
pdfSigner.addDSSAllCerts: (pdf:string | Uint8Array | ArrayBuffer, options?: addDssOptions) => Promise<Uint8Array>
```

### addDssOptions
| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| TSA | [TSASarver](#tsasarver) | Requested |  |
| openPassword | string | If pdf is encrypted<br>Requested | If userpassword,allowed create signature fields. |
| caCerts | Array<string\|Uint8Array> | Optional | Add CA Certificates |
| crls | Array<string\|Uint8Array> | Optional | Add CRLs |
| ignoreMissingTrustChain | boolean | Optional | If true, If trust chain cannot traced,not throw error. |
| ignoreRevokedCert | boolean | Optional | If true, If verification fails or is unknown,not throw error. |

To obtain verification information, CRLs are obtained, OCSP queries are made, and CA certificates are acquired.
Not available in web browsers due to CORS.

---

## ADD LastTimeStamp-DSS
* Add(inculumental) a LastTimeStamp-DSS.<br>
Embeds the verification information of the currently embedded certificate.<br>
Add a DSS without modifying the PDF document.<br>
Existing content, including signatures, will be maintained.<br>
If encrypted,encryption is maintained.<br>
Simply, Extended document Time-stamp.<br>

``` TS
pdfSigner.addDSSLastTimeStamp: (pdf:string | Uint8Array | ArrayBuffer, options?: addDssOptions) => Promise<Uint8Array>
```

### addDssOptions
[see](#adddssoptions)


## encryptPDF

``` TS
const encryptPDF: (pdf: string | Uint8Array | ArrayBuffer, encryptOptions: encryptOptions) => Promise<Uint8Array>
``` 

### encryptOptions
| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| userPassword | string | Requested | If no-userpassword, value is ''(0 length string)  |
| ownerPassword | string | Requested |   |
| permission | UserPermissions | Requested | If all deny,value is {} |
| keyBits | 128\|256 | Optional<br>DEFAULT:256 | Support AES only. |


---

### UserPermission
UserPermission default all deny.
| Name | Type | Attribute | Description |
| --- | --- | --- | --- |
| printing | false|'lowResolution' \| 'highResolution' | Optional | Printing Permission |
| modifying | boolean | Optional | Modify Content Permission |
| copying | boolean | Optional |  Copy or otherwise extract text and graphics from document |
| annotating | boolean | Optional | Permission to add or modify text annotations |
| fillingForms | boolean | Optional | Fill in existing interactive form fields (including signature fields) |
| contentAccessibility | boolean | Optional | Extract text and graphics (in support of accessibility to users with disabilities or for other purposes) |
| documentAssembly | boolean | Optional | Assemble the document (insert, rotate or delete pages and create bookmarks or thumbnail images) |

---

## decryptPDF

``` TS
decryptPDF: (pdf: string | Uint8Array | ArrayBuffer, ownerPassword: string) => Promise<Uint8Array>
```

---

## Use pdf-lib with encryption support.

Import "PDFDocument" from 'pdf-lib_patch' instead of 'pdf-lib'.<br>

### exsample

This then,is 

``` TS
import { PDFDocument, rgb} from "pdf-lib";
const pdfData = await PDFDocument.load(readFileSync("input.pdf"));
const page1 = pdfData.getPage(0);
page1.drawCircle({ "opacity":1, x:100, y:740,size:100,color:rgb(0.8,0.2,0.2)});
page1.drawCircle({ "opacity":1, x:150, y:740,size:100,color:rgb(0.2,0.8,0.2)});
writeFileSync("output.pdf",await pdfData.save());
```

do this.

``` TS
import {rgb} from "pdf-lib";
import {PDFDocument} from "pdf-lib_patch";
const pdfData = await PDFDocument.load(readFileSync("input.pdf"),{"password":"ownerpassword"});
const page1 = pdfData.getPage(0);
page1.drawCircle({ "opacity":1, x:100, y:740,size:100,color:rgb(0.8,0.2,0.2)});
page1.drawCircle({ "opacity":1, x:150, y:740,size:100,color:rgb(0.2,0.8,0.2)});
pdfData.encrypt({
  "keyBits":256,
  "userPassword":"",
  "ownerPassword":"newownerpassword",
  "permission":{"printing":"highResolution"}
});
writeFileSync("output.pdf",await pdfData.save({"useObjectStreams":false}));
//{"useObjectStreams":false} is requested,because pdf broken.
```