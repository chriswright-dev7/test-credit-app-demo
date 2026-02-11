
// Client-side hybrid encryption (RSA-OAEP + AES-GCM) and submission
(async () => {
  function bufToBase64(buf){
    let binary='';
    const bytes=new Uint8Array(buf);
    const len=bytes.byteLength;
    for(let i=0;i<len;i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function base64ToBuf(b64){
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  async function getServerPublicKey(){
    const res = await fetch('/publicKey');
    if(!res.ok) throw new Error('Could not fetch public key');
    const { key } = await res.json();
    return base64ToBuf(key);
  }

  async function encryptPayload(payload){
    const spki = await getServerPublicKey();
    const rsaPub = await window.crypto.subtle.importKey('spki', spki, {name:'RSA-OAEP',hash:'SHA-256'}, false, ['encrypt']);

    const aesKey = await window.crypto.subtle.generateKey({name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
    const rawAes = await window.crypto.subtle.exportKey('raw', aesKey);

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(payload));
    const encrypted = await window.crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, encoded);
    const encryptedArr = new Uint8Array(encrypted);
    const tag = encryptedArr.slice(encryptedArr.length - 16);
    const ciphertext = encryptedArr.slice(0, encryptedArr.length - 16);

    const encryptedKey = await window.crypto.subtle.encrypt({name:'RSA-OAEP'}, rsaPub, rawAes);

    return {
      key: bufToBase64(encryptedKey),
      iv: bufToBase64(iv.buffer),
      ciphertext: bufToBase64(ciphertext.buffer),
      tag: bufToBase64(tag.buffer)
    };
  }

  const form = document.getElementById('secureForm');
  const status = document.getElementById('status');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    status.textContent = 'Encrypting and sending...';
    const payload = {
      firstName: document.getElementById('firstName').value,
      middleInitial: document.getElementById('middleInitial').value,
      lastName: document.getElementById('lastName').value,
      ssn: document.getElementById('ssn').value,
      dob: document.getElementById('dob').value,
      address: document.getElementById('address').value,
      city: document.getElementById('city').value,
      state: document.getElementById('state').value,
      zip: document.getElementById('zip').value,
      annualIncome: document.getElementById('annualIncome').value
    };

    try{
      const encrypted = await encryptPayload(payload);
      const res = await fetch('/submit', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(encrypted)
      });
      if(!res.ok) throw new Error('Server error');
      status.textContent = 'Submission successful.';
      form.reset();
    }catch(err){
      console.error(err);
      status.textContent = 'Submission failed: ' + err.message;
    }
  });
})();