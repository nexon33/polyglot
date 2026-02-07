const $=id=>document.getElementById(id);
const log=m=>{const l=$('log');if(l){l.innerHTML+=m+'\n';l.scrollTop=l.scrollHeight}};
let user='User',port='',connected=false,msgCount=0,pollTimer=null;

async function init(){
    log('[LoRa Chat v6] Android USB Serial');
    log('Scanning for USB devices...');
    getPorts();
}

function getPorts(){
    try{
        const r=polyglot.refresh_ports();
        log('Raw: '+r);
        const ports=JSON.parse(r);
        if(ports.error){
            log('Error: '+ports.error);
            return;
        }
        log('Found: '+ports.join(', '));
        $('ports').innerHTML=ports.map(p=>'<option>'+p+'</option>').join('');
        port=ports[0]||'';
    }catch(e){log('ERR: '+e)}
}

function doConnect(){
    port=$('ports').value;
    user=$('name').value||'User';
    log('Connecting to '+port+'...');
    try{
        const r=polyglot.connect_port(port);
        log('Result: '+r);
        const j=JSON.parse(r);
        if(j.ok){
            connected=true;
            // Update UI
            const conn=document.getElementById('conn');
            const chat=document.getElementById('chat');
            const status=document.getElementById('status');
            if(conn)conn.style.display='none';
            if(chat)chat.style.display='flex';
            if(status){status.className='on';status.textContent='Online';}
            log('Connected! Polling for messages...');
            // Start message polling
            pollTimer=setInterval(pollMessages,500);
        }else{
            log('FAILED: '+(j.error||'unknown'));
        }
    }catch(e){log('ERR: '+e)}
}

function pollMessages(){
    try{
        // Use get_messages if available (Android Java), fall back to mock
        if(typeof polyglot.get_messages==='function'){
            const r=polyglot.get_messages(msgCount);
            const j=JSON.parse(r);
            if(j.messages&&j.messages.length>0){
                j.messages.forEach(addMessage);
            }
            msgCount=j.total||msgCount;
        }
    }catch(e){}
}

function addMessage(m){
    const isMe=m.startsWith(user+':');
    const parts=m.split(':');
    const sender=parts[0]||'?';
    const text=parts.slice(1).join(':')||m;
    const msgs=$('msgs');
    if(msgs){
        msgs.innerHTML+='<div class="m'+(isMe?' mine':'')+'"><b>'+sender+':</b> '+text+'</div>';
        msgs.scrollTop=msgs.scrollHeight;
    }
}

function doSend(){
    const m=$('msg').value.trim();
    if(!m||!connected)return;
    const fullMsg=user+':'+m;
    log('TX: '+fullMsg);
    try{
        if(polyglot.send_message(fullMsg)){
            $('msg').value='';
        }else{
            log('Send failed');
        }
    }catch(e){log('ERR: '+e)}
}

window.onload=init;