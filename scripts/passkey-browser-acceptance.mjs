// Actual WebAuthn proof rejection using Chrome virtual authenticator controls.
// Caller owns an isolated browser/profile and a localhost PostgreSQL fixture.
export async function rejectAssertion({page,cdp,authenticator,base,override}) {
  const response=await fetch(base+"/v2/auth/passkeys/start",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({registration:false})});
  if(response.status!==200)throw new Error("start "+response.status);
  const flow=await response.json();
  await page.goto(flow.authorization_url,{waitUntil:"domcontentloaded"});
  await cdp.send("WebAuthn.setResponseOverrideBits",{authenticatorId:authenticator.authenticatorId,...override});
  const result=await page.evaluate(async()=>{
    const path="/v2/auth/passkeys/";const query="?flow_id="+settings.id;
    const options=await fetch(path+"options"+query,{headers:{"x-nds-csrf":settings.csrf},credentials:"same-origin"});
    const credential=await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON((await options.json()).publicKey)});
    const request={method:"POST",headers:{"x-nds-csrf":settings.csrf,"content-type":"application/json"},credentials:"same-origin",body:JSON.stringify(credential.toJSON())};
    const rejected=await fetch(path+"verify"+query,request);
    const replay=await fetch(path+"verify"+query,request);
    return {rejected:rejected.status,replay:replay.status};
  });
  await cdp.send("WebAuthn.setResponseOverrideBits",{authenticatorId:authenticator.authenticatorId,isBogusSignature:false,isBadUV:false,isBadUP:false});
  const exchange=await fetch(base+"/v2/auth/passkeys/exchange",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({flow_id:flow.flow_id,exchange_token:flow.exchange_token})});
  if(result.rejected!==401||result.replay!==401||exchange.status!==401)throw new Error("Invalid proof or replay issued a session");
  return {badProofRejected:true,replayRejected:true,exchangeTerminal:true};
}
