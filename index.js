'use strict';

// This is built on https://github.com/digitalbazaar/vc-js 

// We're exploring using did:web, so we can add value to DOIs...
// https://w3c-ccg.github.io/did-method-web/
// https://github.com/decentralized-identity/web-did-resolver


// (Also useful: https://github.com/digitalbazaar/did-cli)

var fs = require("fs");
const {extendContextLoader} = require('jsonld-signatures');
const vc = require('vc-js');
//const myCustomContext = require('./myCustomContext');
const jsigs = require('jsonld-signatures');
const {AssertionProofPurpose} = jsigs.purposes;
const {CredentialIssuancePurpose} = require('vc-js');
const express = require('express')
const app = express()
const port = 3000

//const didContext = require('./lib/contexts');
const {keyToDidDoc} = require('did-method-key').driver();
const {Ed25519KeyPair} = require('crypto-ld');
const {Ed25519VerificationKey2018} = jsigs.suites;
const {Ed25519Signature2018} = jsigs.suites;
const {defaultDocumentLoader} = vc;
const driver = require('did-method-key').driver();
const request = require('request');

app.use(express.urlencoded())
const bodyParser = require('body-parser');
app.use(bodyParser());

app.get('/', async(req,res)=> {
//console.log("input-----11111", req.body);
const ide = req.body.uIdentifier
//const result = await issueCredential(ide);
res.sendFile(__dirname + '/credentialRequest.html');
})

app.get('/verify',async(req,res) => {

res.sendFile(__dirname + '/credentialVerify.html');

})

app.post('/issueCredential', async(req,res) => {

const ide = req.body.ide
console.log("I GOT IDE----!111", ide);
const result = await issueCredential(ide);

res.send(JSON.stringify(result));
})

app.post('/verifyCredential', async(req,res) => {
 const cred = req.body.cred;
 console.log("cred to verify", cred)
 const result =  await verifyCredential(cred);
 res.send(JSON.stringify(result));


})


// on the actual issuer I believe this would be an ed25519
// key pair that a wallet has authorized the issuer to use.

let issuerKeyPair, issuerKeyDid = null;
let subjectKeyPair, subjectKeyDid = null;
let presentation = null;

// just gets the assertion method from the did key.
const getAssertionMethod = didKey => {
  return didKey.assertionMethod[0];
};

// This is really an admin function of vc-js in order to resolved DIDdocs from keys, etc.
// Should really be in its own file...

const documentLoader = extendContextLoader(async url => {
  // this fetches the entire did document
  // this fetches a specific a key from a did doc by fingerPrint

  // IB: This is how DIDs are resolved to their DIDdocs...
     console.log("Looking for " + url)

  // Don't think this top block is used by me so far - I think it resolves different DID types
  if(issuerKeyDid['@context'] === url) {
    return {
      contextUrl: null,
      documentUrl: url,
      // this did key's context should resolve
      // to the latest did-context
      document: didContext.contexts.get('https://w3id.org/did/v1')
    };
  }

  // The next two clauses resolved a did:key document, which is self resolvable to its DIDdoc/JSON-LD
  if(url.startsWith('did:key') && url.includes('#')) {
    const did = url.split('#')[0];

    const didKey = await driver.get({did});
    let doc = null;
    for(const prop in didKey) {
      const property = didKey[prop];
      if(Array.isArray(property)) {
        [doc] = property.filter(p => p.id === url);
      }
      if(property.id === url) {
        doc = didKey[prop];
      }
      if(doc) {
        break;
      }
    }
    doc['@context'] = 'https://w3id.org/security/v2';
    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }

  if(url.startsWith('did:key')) {
    const did = url.split('#')[0];
    const doc = await driver.get({did});
    doc['@context'] = 'https://w3id.org/security/v2';

    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    }
  }

  // this adds schema.org's JSON-LD context to the documentLoader
  // the demo credential's type is from schema.org
  // IB - I haven't used this yet... 
  if(url === 'https://schema.org/') {
    return {
      contextUrl: null,
      documentUrl: url,
      document: schemaContext
    };
  }

   if (url.startsWith("http://"))
  {
    console.log("Pulling from: ", url, "\n")
    let docString = await downloadPage(url)
    let doc = JSON.parse(docString);

//    console.log("Fetched from ", url, ":\n", doc, "\n")

    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }

  if (url.startsWith("https://"))
  {
  //  console.log("Pulling from: ", url, "\n")
    let docString = await downloadPage(url)
    let doc = JSON.parse(docString);

   // console.log("Fetched from ", url, ":\n", doc, "\n")

    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }

    if(url.startsWith('did:web:5da4bff0cc895d0f7435d48b'))
{
    //console.log(" i am in the did resolver for subject");
    url = 'http://www.craftofscience.xyz/testTaledid.json'
     console.log("Pulling from: ", url, "\n")
    let docString = await downloadPage(url)
    let doc = JSON.parse(docString);

   // console.log("Fetched from ", url, ":\n", doc, "\n")

    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
}



    if (url.startsWith('did:web')) 
 {
   console.log(" i am in the did resolver for issuer");

    url = 'http://www.craftofscience.xyz/did.json'
 
   // console.log("Pulling from: ", url, "\n")
    let docString = await downloadPage(url)
    let doc = JSON.parse(docString);

   // console.log("Fetched from ", url, ":\n", doc, "\n")

    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }



   /*if(url === 'http://www.craftofscience.xyz/custContext.jsonld') {
    console.log("I am here in this resolver");
    url = "http://www.craftofscience.xyz/did.json"

    let docString = await downloadPage(url)
    
    let doc = JSON.parse(docString);
   // console.log("did doc from url", doc);

    doc['@context'] = 'https://w3id.org/security/v2';
    

   // console.log("DID Doc fetched from did:web URL:\n", doc, "\n")

    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }*/
  
  return defaultDocumentLoader(url);

});

/*const documentLoader = extendContextLoader(async url => {
  if(url == 'did:web:craftofscience.xyz') {

   url = "http://www.craftofscience.xyz/did.json"
   let docString = await downloadPage(url)
   console.log("-----------docString-------");
   let doc = JSON.parse(docString)
    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }
  return defaultDocumentLoader(url);
});*/


function downloadPage(url) {
  return new Promise((resolve, reject) => {
      request(url, (error, response, body) => {
          if (error) reject(error);
          if (response.statusCode != 200) {
              reject('Invalid status code <' + response.statusCode + '>');
          }
          resolve(body);
      });
  });
}

app.listen(port, () => console.log(`Example app listening on port ${port}!`))

async function setupIssuerKeyPair() {
  // this produces a keypair with private key material
  // in a real situation, subject might provide their DID 

   const privateKeyBase58 = '4H66UGVXEoK2EHMS75eWEjHBwF2CTrPdcYsLSoXLxromDfcZUhCPiiVkLbJAXxrL8M8y7YTQpbb5EKqc9NnN9S3L'
const options = {
    publicKeyBase58: 'B1BoAENvkZFa1EMnXksUUg1JFeZGAg2CWrLYMzdquA4i',
    privateKeyBase58
  };
  
  issuerKeyPair = new Ed25519KeyPair(options);
  console.log("---------issuerkeypair", issuerKeyPair);
  issuerKeyPair.id = 'did:web:craftofscience.xyz#' + issuerKeyPair.fingerprint();
  //issuerKeyDid = keyToDidDoc(issuerKeyPair);
  //console.log("issuerKeyDid", issuerKeyDid);
   issuerKeyDid = {"id" : "did:web:craftofscience.xyz"}

}

/*
  issuer and subject are same in this example
  in a real-world scenario, subject's DID also needs to be published
  in a resolvable URL like did.json published for issuer.
  setupSubjectKeyPair needs to be changed accordingly.

*/
async function setupSubjectKeyPair() {
  // this produces a keypair with private key material
  // in a real situation, subject might provide their DID 
  
  console.log("Lets go with the subject DID now");

  /*const privateKeyBase58 = '4H66UGVXEoK2EHMS75eWEjHBwF2CTrPdcYsLSoXLxromDfcZUhCPiiVkLbJAXxrL8M8y7YTQpbb5EKqc9NnN9S3L'
const options = {
    publicKeyBase58: 'B1BoAENvkZFa1EMnXksUUg1JFeZGAg2CWrLYMzdquA4i',
    privateKeyBase58
  };*/

  const {Ed25519KeyPair} = require('crypto-ld');
  const keyPair = await Ed25519KeyPair.generate();
  const privateKeyBase58 = keyPair.privateKeyBase58;
  const options = {
     publicKeyBase58: keyPair.publicKeyBase58,
     privateKeyBase58
 
 };
  subjectKeyPair = new Ed25519KeyPair(options);
  
   subjectKeyPair.id = 'did:web:5da4bff0cc895d0f7435d48b#' + subjectKeyPair.fingerprint();
  subjectKeyDid = {"id":"did:web:5da4bff0cc895d0f7435d48b"}
   console.log("\n\nsubjectkey pair +++++", subjectKeyPair);
  //console.log(await subjectKeyPair.export()); 
}



async function  issueCredential (ide) {


 await setupIssuerKeyPair();
 await setupSubjectKeyPair();

 console.log("Credential issuing service...\n");
 
 const credentialString = fs.readFileSync("/Users/sradha/PhD_Research_2020/digitalbazaar_experiments/credential.json").toString();
 //console.log(credentialString);
 //console.log(JSON.parse(credentialString)); 
 const credential = JSON.parse(credentialString);
 
 credential.issuer = issuerKeyDid.id;
 console.log("i am going to use ide", ide);
 credential.credentialSubject.id = subjectKeyDid.id + '/'+ ide
 //console.log("credential issuer id", credential.issuer.id);
 //console.log("credential subject id", credential.credentialSubject.id);
 credential.issuanceDate = (new Date()).toISOString()
 const verMethod = 'did:web:craftofscience.xyz#' + issuerKeyPair.fingerprint();
 console.log("!!! assertion proof !!!", (new AssertionProofPurpose()));
// console.log("issuerKeyDid", issueKeyDid);
 const signingSuite = new Ed25519Signature2018({
 
  //verificationMethod: getAssertionMethod(issuerKeyDid),
  purpose: new AssertionProofPurpose(),
  key: issuerKeyPair,
  verificationMethod: issuerKeyPair.id
});
//console.log("suite method\n\n", signingSuite.verificationMethod);
console.log("\nsigning suite", signingSuite);
 //console.log("verification method", signingSuite.verificationMethod);
  const issuedCred = await vc.issue({credential,suite: signingSuite,documentLoader: documentLoader});
    fs.writeFileSync("./issuedCredential.json", JSON.stringify(issuedCred, null, 4))
 
// issue and verify in one function. should separate

   const issuedCredentialString = fs.readFileSync("./issuedCredential.json").toString();
     const issuedCredential = JSON.parse(issuedCredentialString);
     console.log("credential I read from the file -----\n", issuedCredential); 
   /* const verifySuite = new Ed25519Signature2018();
    const verifiedCredential = await vc.verifyCredential({credential: issuedCredential, suite: verifySuite, documentLoader:documentLoader});
      console.log("ver cred", verifiedCredential);

     if (verifiedCredential.verified == false)
     {
         console.log('CREDENTIAL NOT VERIFIED:\n', JSON.stringify(verifiedCredential));
         throw "Credential not verified";
     }
     else
         console.log('CREDENTIAL VERIFIED:\n', JSON.stringify(verifiedCredential.results),'\n');
*/
     return (issuedCredential);
   
  
 

};

async function  verifyCredential (cred) {
  
     //const verifySuite = new Ed25519Signature2018();

     console.log("Verify the credential we've been presented with...");
     const verifySuite = new Ed25519Signature2018();
     const credToVerify = cred;

     const issuedCredential = JSON.parse(credToVerify);
        
     const verifiedCredential = await vc.verifyCredential({credential: issuedCredential, suite: verifySuite, documentLoader:documentLoader});
     console.log("ver cred", verifiedCredential);
 
     if (verifiedCredential.verified == false)
     {
         console.log('CREDENTIAL NOT VERIFIED:\n', JSON.stringify(verifiedCredential));
         throw "Credential not verified";
     }
     else
         console.log('CREDENTIAL VERIFIED:\n', JSON.stringify(verifiedCredential.results),'\n');
        
    return (verifiedCredential);
   };


async function createPresentation()
{
   
    //await setupIssuerKeyPair();
    //await setupSubjectKeyPair();
     console.log("subjectkey pair in create presentation\n +++++", subjectKeyPair);

    const signingSuite = new Ed25519Signature2018({
       purpose: new AssertionProofPurpose(),
       key: issuerKeyPair
     });
    
     const subjectSuite = new Ed25519Signature2018({
       purpose: new AssertionProofPurpose(),
       key: subjectKeyPair
     });

    const verifiableCredentialString = fs.readFileSync("./issuedCredential.json").toString(); 
    const verifiableCredential = JSON.parse(verifiableCredentialString);
    presentation = vc.createPresentation({verifiableCredential});
   
    console.log("--------unsigned presentation---------\n", JSON.stringify(presentation));
    //console.log("==== signed presentation ===\n", JSON.stringify(signedPresentation, null, 2));
};

async function signPresentation()
{
  console.log("subjectkey pair in create presentation\n +++++", subjectKeyPair);
  const subjectSuite = new Ed25519Signature2018({
       purpose: new AssertionProofPurpose(),
       key: subjectKeyPair
     });
   console.log("--------unsigned presentation---------\n", JSON.stringify(presentation));
   
   

   const signedPresentation = await vc.signPresentation({presentation, suite: subjectSuite, challenge:"567", documentLoader:documentLoader});
   console.log("Signed Presentation\n", signedPresentation);
   console.log(JSON.stringify(signedPresentation,null,2));
   console.log("-----VERIFY PROOF -----\n");
   const verifySuite = new Ed25519Signature2018();
   console.log("Verifying proof...");
   
   const result = await vc.verify({presentation: signedPresentation, suite: verifySuite, challenge:"567", documentLoader:documentLoader}); 
    if(result.verified ==  true)
{
    console.log("Is verified?", result.verified);
    console.log(JSON.stringify(signedPresentation.verifiableCredential));
}
};




/*(async ()=>{
  //await setupIssuerKeyPair();
 //await setupSubjectKeyPair();

try {

  await setupIssuerKeyPair();
 await setupSubjectKeyPair();
  await issueCredential();
 // await verifyCredential();
  await createPresentation();
  await signPresentation();
} catch (error) {
  console.log('That did not go well.')
  throw error
}
 //await issueCredential();
})();*/


