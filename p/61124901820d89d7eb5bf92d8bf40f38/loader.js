'use strict';
// Opening another full bearer link in the same tab can otherwise be a hash-only navigation.
addEventListener('hashchange',()=>{document.getElementById('preview').replaceChildren();location.reload();});
(async()=>{
  let fragment=location.hash;
  history.replaceState(null,'',location.pathname+location.search);
  const status=document.getElementById('status');
  const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  try {
    if(!/^#k=[A-Za-z0-9_-]{43}$/.test(fragment)) throw Error();
    let raw=decode(fragment.slice(3).replace(/-/g,'+').replace(/_/g,'/')+'=');
    fragment='';
    const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']); raw.fill(0); raw=null;
    const response=await fetch('./bundle.json',{credentials:'omit',referrerPolicy:'no-referrer',cache:'no-store'});
    if(!response.ok) throw Error();
    const envelope=await response.json();
    if(Object.keys(envelope).sort().join(',')!=='algorithm,ciphertext,id,nonce,version' || envelope.version!==1 || envelope.algorithm!=='AES-256-GCM' || !/^[a-f0-9]{32}$/.test(envelope.id)) throw Error();
    const nonce=decode(envelope.nonce), ciphertext=decode(envelope.ciphertext);
    if(nonce.length!==12 || ciphertext.length<16 || ciphertext.length>30*1024*1024) throw Error();
    const aad=new TextEncoder().encode(`verto-preview:${envelope.version}:${envelope.id}`);
    const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,ciphertext);
    const html=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    const frame=document.createElement('iframe');
    frame.title='Персональное превью'; frame.referrerPolicy='no-referrer';
    frame.setAttribute('sandbox','allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox');
    // The only cross-boundary message is a bounded integer height from this exact window.
    addEventListener('message',event=>{
      const data=event.data;
      if(event.source!==frame.contentWindow || event.origin!=='null' || !data || typeof data!=='object' || Object.keys(data).sort().join(',')!=='height,type' || data.type!=='preview-height' || !Number.isInteger(data.height) || data.height<100 || data.height>50000) return;
      frame.style.height=data.height+'px';
    });
    frame.srcdoc=html; document.getElementById('preview').append(frame); status.hidden=true;
  } catch {
    fragment=''; status.textContent='Превью не удалось открыть. Проверьте полную ссылку у отправителя.';
  }
})();
