const button=document.getElementById('continue');
const output=document.getElementById('result');
button.onclick=async()=>{
  button.disabled=true;
  try {
    const path='/v2/auth/passkeys/';
    const query='?flow_id='+encodeURIComponent(settings.id);
    const headers={'x-nds-csrf':settings.csrf};
    const response=await fetch(path+'options'+query,{headers,credentials:'same-origin',cache:'no-store'});
    if(!response.ok)throw new Error('request');
    const options=await response.json();
    const parse= settings.registration ? PublicKeyCredential.parseCreationOptionsFromJSON : PublicKeyCredential.parseRequestOptionsFromJSON;
    if(typeof parse!=='function')throw new Error('unsupported');
    const publicKey=parse.call(PublicKeyCredential,options.publicKey);
    const credential= settings.registration ? await navigator.credentials.create({publicKey}) : await navigator.credentials.get({publicKey});
    const verified=await fetch(path+'verify'+query,{method:'POST',headers:{...headers,'content-type':'application/json'},credentials:'same-origin',cache:'no-store',body:JSON.stringify(credential.toJSON())});
    if(!verified.ok)throw new Error('request');
    output.textContent=document.documentElement.lang==='ru'?'Готово. Вернитесь в приложение NDS.':'Complete. Return to the NDS application.';
  }catch(_){
    output.textContent=document.documentElement.lang==='ru'?'Ключ доступа не подтверждён. Начните вход заново в NDS.':'Passkey was not verified. Start again in NDS.';
  }
};
