'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,ROOT=__dirname,COOKIE='sg_admin_session',TTL=8*60*60;
const MIME={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.webp':'image/webp','.svg':'image/svg+xml','.json':'application/json; charset=utf-8','.ico':'image/x-icon'};
function json(res,status,obj){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(obj));}
function equal(a,b){const x=Buffer.from(String(a||'')),y=Buffer.from(String(b||''));return x.length===y.length&&crypto.timingSafeEqual(x,y);}
function secret(){return process.env.ADMIN_SESSION_SECRET||'';}
function sig(v){return crypto.createHmac('sha256',secret()).update(v).digest('base64url');}
function token(){const p=Buffer.from(JSON.stringify({u:process.env.ADMIN_USERNAME,exp:Math.floor(Date.now()/1000)+TTL})).toString('base64url');return p+'.'+sig(p);}
function authed(req){if(!secret()||!process.env.ADMIN_USERNAME)return false;const c=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));if(!c)return false;const t=c.slice(COOKIE.length+1).split('.');if(t.length!==2||!equal(t[1],sig(t[0])))return false;try{const d=JSON.parse(Buffer.from(t[0],'base64url').toString());return d.u===process.env.ADMIN_USERNAME&&d.exp>Date.now()/1000;}catch{return false;}}
function cookie(req,res,value,max){const secure=req.headers['x-forwarded-proto']==='https'||!!req.socket.encrypted;res.setHeader('Set-Cookie',COOKIE+'='+value+'; HttpOnly; Path=/; SameSite=Strict; Max-Age='+max+(secure?'; Secure':''));}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>8192){reject(Error('large'));req.destroy();}});req.on('end',()=>{try{resolve(JSON.parse(s||'{}'));}catch{reject(Error('json'));}});req.on('error',reject);});}
const attempts=new Map();
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost'),p=decodeURIComponent(url.pathname);
 if(p==='/api/admin/session'&&req.method==='GET')return json(res,200,{authenticated:authed(req)});
 if(p==='/api/admin/login'&&req.method==='POST'){
  if(!process.env.ADMIN_USERNAME||!process.env.ADMIN_PASSWORD||!secret())return json(res,503,{error:'Render Environment-এ ADMIN_USERNAME, ADMIN_PASSWORD এবং ADMIN_SESSION_SECRET সেট করুন।'});
  const ip=req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown',now=Date.now(),a=attempts.get(ip);
  if(a&&now-a.start<900000&&a.count>=8)return json(res,429,{error:'অনেকবার চেষ্টা হয়েছে। ১৫ মিনিট পরে আবার চেষ্টা করুন।'});
  try{const b=await body(req);const ok=equal(b.username,process.env.ADMIN_USERNAME)&equal(b.password,process.env.ADMIN_PASSWORD);if(!ok){if(!a||now-a.start>=900000)attempts.set(ip,{start:now,count:1});else a.count++;return json(res,401,{error:'Username অথবা Password সঠিক নয়।'});}attempts.delete(ip);cookie(req,res,token(),TTL);return json(res,200,{ok:true});}catch{return json(res,400,{error:'তথ্য সঠিকভাবে পাঠানো হয়নি।'});}
 }
 if(p==='/api/admin/logout'&&req.method==='POST'){cookie(req,res,'',0);return json(res,200,{ok:true});}
 if(p.startsWith('/api/admin/')){if(!authed(req))return json(res,401,{error:'Unauthorized'});return json(res,404,{error:'এই Admin API এখনো তৈরি করা হয়নি।'});}
 let target=p==='/admin'||p==='/admin/'?'/admin.html':p;
 if(target==='/'||target==='/index.html')target='/FFX.html';
 const file=path.resolve(ROOT,'.'+target),rel=path.relative(ROOT,file);
 if(rel.startsWith('..')||path.isAbsolute(rel)){res.writeHead(403);return res.end('403 Forbidden');}
 fs.stat(file,(err,st)=>{if(err||!st.isFile()){res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});return res.end('404 Not Found');}
  res.writeHead(200,{'Content-Type':MIME[path.extname(file).toLowerCase()]||'application/octet-stream','X-Content-Type-Options':'nosniff','Cache-Control':path.extname(file)==='.html'?'no-store':'public, max-age=3600'});
  const stream=fs.createReadStream(file);stream.on('error',()=>{if(!res.headersSent)res.writeHead(500);res.end('500 Internal Server Error');});stream.pipe(res);
 });
});
server.listen(PORT,'0.0.0.0',()=>console.log('Server running on port '+PORT));
