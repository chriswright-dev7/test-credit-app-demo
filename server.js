const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// const mongoUri = process.env.MONGODB_URI || "mongodb+srv://admin_db_user:<db_password>@cluster0.b9uzdvz.mongodb.net/?appName=Cluster0";
const { MongoClient, ServerApiVersion } = require('mongodb');
const mongoUri = "mongodb+srv://admin_db_user:<db_password>@cluster0.b9uzdvz.mongodb.net/?appName=Cluster0";


// Load or generate RSA key pair
const keyDir = path.join(__dirname, 'keys');
if(!fs.existsSync(keyDir)) fs.mkdirSync(keyDir);
const privPath = path.join(keyDir, 'private.pem');
const pubPath = path.join(keyDir, 'public.pem');
if(!fs.existsSync(privPath) || !fs.existsSync(pubPath)){
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {modulusLength: 4096});
  fs.writeFileSync(privPath, privateKey.export({type:'pkcs1', format:'pem'}));
  fs.writeFileSync(pubPath, publicKey.export({type:'spki', format:'pem'}));
}

const privatePem = fs.readFileSync(privPath, 'utf8');
const publicPem = fs.readFileSync(pubPath, 'utf8');

// MongoDB client
const mongoClient = new MongoClient(mongoUri);
let submissionsCollection;
async function initDb(){
  await mongoClient.connect();
  const db = mongoClient.db(process.env.MONGODB_DBNAME || 'secure_form_demo');
  submissionsCollection = db.collection('CreditDemoDB');
  await submissionsCollection.createIndex({ created_at: 1 });
}

// // Create a MongoClient with a MongoClientOptions object to set the Stable API version
// const client = new MongoClient(uri, {
//   serverApi: {
//     version: ServerApiVersion.v1,
//     strict: true,
//     deprecationErrors: true,
//   }
// });
// async function run() {
//   try {
//     // Connect the client to the server	(optional starting in v4.7)
//     await client.connect();
//     // Send a ping to confirm a successful connection
//     await client.db("admin").command({ ping: 1 });
//     console.log("Pinged your deployment. You successfully connected to MongoDB!");
//   } finally {
//     // Ensures that the client will close when you finish/error
//     await client.close();
//   }
// }
// run().catch(console.dir);

// -------------------------------------------------------------

app.get('/publicKey', (req, res) => {
  // Return spki DER base64 for browser import
  const spki = crypto.createPublicKey(publicPem).export({type:'spki', format:'der'});
  res.json({ key: spki.toString('base64') });
});

app.post('/submit', async (req, res) => {
  try{
    const { key, iv, ciphertext, tag } = req.body;
    if(!key || !iv || !ciphertext || !tag) return res.status(400).send('Missing fields');

    const encryptedKey = Buffer.from(key, 'base64');
    const rawAes = crypto.privateDecrypt({key: privatePem, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, encryptedKey);

    const ivBuf = Buffer.from(iv, 'base64');
    const ct = Buffer.from(ciphertext, 'base64');
    const tagBuf = Buffer.from(tag, 'base64');
    const combined = Buffer.concat([ct, tagBuf]);

    const decipher = crypto.createDecipheriv('aes-256-gcm', rawAes, ivBuf);
    decipher.setAuthTag(tagBuf);
    const decrypted = Buffer.concat([decipher.update(combined), decipher.final()]);
    const payload = JSON.parse(decrypted.toString('utf8'));

    if(!submissionsCollection) return res.status(500).send('DB not initialized');
    const doc = {
      created_at: new Date(),
      applicationId: (()=>{const d=new Date(); return `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}${String(d.getMinutes()).padStart(2,'0')}${String(d.getMilliseconds()).padStart(3,'0')}`})(),
      sessionId: crypto.randomUUID(),
      firstName: payload.firstName,
      middleInitial: payload.middleInitial,
      lastName: payload.lastName,
      ssn: payload.ssn,
      dob: payload.dob,
      address: payload.address,
      city: payload.city,
      state: payload.state,
      zip: payload.zip,
      annualIncome: payload.annualIncome ? parseFloat(payload.annualIncome) : null
    };
    await submissionsCollection.insertOne(doc);
    res.sendStatus(200);
  }catch(err){
    console.error(err);
    res.status(500).send('Decryption or storage failed');
  }
});

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(PORT, ()=> console.log(`Server running on http://localhost:${PORT}`));
}).catch(err => {
  console.error('Failed to initialize MongoDB:', err);
  process.exit(1);
});
