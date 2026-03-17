import{connect}from'cloudflare:sockets'

const C={
  sub:'k3f',
  uuid:'7c16fd94-bdd1-43dd-b406-fcae7c4efb27',
  fallback:'ProxyIP.KR.CMLiussss.net',
  hdrs:{'cache-control':'public,max-age=14400','content-type':'text/plain'}
}

// ✅ 全局初始化，只执行一次（不包含 redirect）
const ERR4=new Response(null,{status:400})
const ERR5=new Response(null,{status:502})
const uuidBytes=new Uint8Array(16)
const decoder=new TextDecoder()
const urlCache=new Map()
const MAX_URL_CACHE=32

// ✅ 初始化 UUID
for(let i=0,hex=C.uuid.replace(/-/g,'');i<32;i+=2)
  uuidBytes[i>>1]=parseInt(hex.substr(i,2),16)

let nodeList=['www.visa.cn:443']
let stmt

// ✅ 高效的 Base64 转换
const base64ToUint8Array=(str)=>{
  str=str.replace(/-/g,'+').replace(/_/g,'/')
  const padding=(4-(str.length%4))%4
  if(padding>0)str+='='.repeat(padding)
  const bin=atob(str)
  const len=bin.length
  const arr=new Uint8Array(len)
  for(let i=0;i<len;i++)arr[i]=bin.charCodeAt(i)
  return arr
}

// ✅ 高效的 IPv6 地址构建
const buildIPv6=(buf,start)=>{
  const parts=[]
  for(let i=0;i<8;i++)
    parts.push(((buf[start+i*2]<<8)|buf[start+i*2+1]).toString(16))
  return'['+parts.join(':')+']'
}

const validateProtocol=buf=>{
  for(let i=16;i--;)if(buf[i+1]!==uuidBytes[i])return false
  return true
}

const parseTarget=(buf,offset)=>{
  if(offset+3>buf.length)throw new Error('Buffer too short')
  const port=buf[offset]<<8|buf[offset+1]
  const type=buf[offset+2]
  const start=offset+3
  
  if(type&1){
    if(start+4>buf.length)throw new Error('Buffer too short for IPv4')
    return{host:`${buf[start]}.${buf[start+1]}.${buf[start+2]}.${buf[start+3]}`,port,end:start+4}
  }
  if(type&4){
    if(start+16>buf.length)throw new Error('Buffer too short for IPv6')
    return{host:buildIPv6(buf,start),port,end:start+16}
  }
  
  if(start>=buf.length)throw new Error('Buffer too short for domain')
  const len=buf[start]
  if(start+1+len>buf.length)throw new Error('Buffer too short for domain content')
  return{host:decoder.decode(buf.subarray(start+1,start+1+len)),port,end:start+1+len}
}

const buildVs=(ip,name,host)=>{
  const sepIdx=ip.indexOf('#')
  const endpoint=sepIdx>-1?ip.substring(0,sepIdx):ip
  const tag=sepIdx>-1?ip.substring(sepIdx+1):name||''
  
  let displayIp,port='443'
  if(endpoint[0]==='['){
    const bracket=endpoint.indexOf(']')
    displayIp=endpoint.substring(0,bracket+1)
    const rest=endpoint.substring(bracket+1)
    if(rest[0]===':'){
      const colonIdx=rest.indexOf(':',1)
      port=colonIdx>-1?rest.substring(1,colonIdx):rest.substring(1)
    }
  }else{
    const colon=endpoint.indexOf(':')
    if(colon>-1){
      displayIp=endpoint.substring(0,colon)
      port=endpoint.substring(colon+1)
    }else{
      displayIp=endpoint
    }
  }
  
  const finalTag=tag||displayIp.replace(/\./g,'-')+'-'+port
  return`vless://${C.uuid}@${displayIp}:${port}?encryption=none&security=tls&type=ws&host=${host}&path=%2F%3Fed%3D2560&sni=${host}#${encodeURIComponent(finalTag)}`
}

export default{
  async fetch(req,env,ctx){
    // ✅ 在处理器内部创建 REDIRECT（只在需要时创建）
    let redirect
    
    // ✅ 获取 URL（高效 LRU 缓存）
    let url=urlCache.get(req.url)
    if(!url){
      if(urlCache.size>=MAX_URL_CACHE){
        const firstKey=urlCache.keys().next().value
        urlCache.delete(firstKey)
      }
      url=new URL(req.url)
      urlCache.set(req.url,url)
    }
    
    const{host,pathname}=url
    
    if(req.headers.get('upgrade')==='websocket'){
      const proto=req.headers.get('sec-websocket-protocol')
      if(!proto)return ERR4
      
      let buf,len
      try{
        buf=base64ToUint8Array(proto)
        len=buf.length
      }catch{
        return ERR4
      }
      
      if(len<18||!validateProtocol(buf)){
        return ERR4
      }
      
      let targetHost,targetPort,end
      try{
        const offset=19+buf[17]
        const parsed=parseTarget(buf,offset)
        targetHost=parsed.host
        targetPort=parsed.port
        end=parsed.end
      }catch{
        return ERR4
      }
      
      let socket
      try{
        socket=connect({hostname:targetHost,port:targetPort})
        await socket.opened
      }catch{
        try{
          socket=connect({hostname:C.fallback,port:443})
          await socket.opened
        }catch{
          return ERR5
        }
      }
      
      const[client,server]=Object.values(new WebSocketPair())
      server.accept()
      
      try{
        server.send(new Uint8Array(2))
      }catch{
        return ERR5
      }
      
      let writer
      try{
        writer=socket.writable.getWriter()
      }catch{
        return ERR5
      }
      
      if(len>end){
        const payload=buf.subarray(end,len)
        writer.write(payload).catch(()=>{})
      }
      
      server.addEventListener('message',e=>{
        writer.write(e.data).catch(()=>{})
      })
      
      const cleanup=()=>{
        try{writer.releaseLock()}catch{}
      }
      server.addEventListener('close',cleanup)
      server.addEventListener('error',cleanup)
      
      socket.readable.pipeTo(new WritableStream({
        write(chunk){
          try{
            server.send(chunk)
          }catch{}
        }
      })).catch(()=>{})
      
      return new Response(null,{status:101,webSocket:client})
    }
    
    if(pathname===`/${C.sub}/dy`){
      try{
        stmt??=env.DB.prepare('SELECT ip,name FROM ips WHERE active=1 ORDER BY id ASC')
        const{results}=await stmt.all()
        if(results[0])nodeList=results.map(r=>r.ip+(r.name?'#'+r.name:''))
      }catch{}
      return new Response(nodeList.map(ip=>buildVs(ip,'',host)).join('\n'),{headers:C.hdrs})
    }
    
    if(pathname===`/${C.sub}`){
      return new Response(`订阅: https://${host}/${C.sub}/dy`,{headers:C.hdrs})
    }
    
    // ✅ 在处理器内部创建 redirect
    redirect=Response.redirect('https://github.com/Meibidi/kuangbao',302)
    return redirect
  }
}
