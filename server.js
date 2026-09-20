// Durosak Plus API V6 — server-mediated content + device controls + signed video relay
// Firestore = educational content (server-side only)
// Firebase RTDB = student accounts/devices
// IMPORTANT: media is NEVER redirected to the origin; /api/video/stream streams bytes through this server.

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.API_JWT_SECRET || '';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const RTDB_URL = String(process.env.FIREBASE_RTDB_URL || '').replace(/\/$/, '');
const STUDENTS_PATH = 'Durosak Student';
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || '').split(',').map(x=>x.trim()).filter(Boolean);
const ACCESS_TTL_SECONDS = Math.min(Math.max(Number(process.env.ACCESS_TTL_SECONDS)||3600,300),86400);
const VIDEO_TOKEN_TTL_SECONDS = 3 * 60 * 60;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const MAX_DEVICES_DEFAULT = 1;
const BUNNY_API_KEY = process.env.BUNNY_API_KEY || '';
const BUNNY_API_BASE = 'https://video.bunnycdn.com/library';

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({crossOriginResourcePolicy:{policy:'cross-origin'}}));
app.use(cors({
  origin(origin,cb){
    // Allow requests with no Origin (curl/server-to-server) and local file:// pages (Origin: null).
    // If ALLOWED_ORIGINS contains '*', allow any origin.
    if(!origin || origin==='null' || !ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)){
      return cb(null,true);
    }
    return cb(new Error('CORS_ORIGIN_NOT_ALLOWED'));
  },
  credentials:true,
  methods:['GET','POST','PATCH','DELETE','OPTIONS'],
  allowedHeaders:['Content-Type','Authorization','X-Device-Id','Range']
}));
app.use(express.json({limit:'256kb'}));

const generalLimiter = rateLimit({windowMs:60*1000,limit:120,standardHeaders:'draft-8',legacyHeaders:false,message:{success:false,error:'RATE_LIMITED',message:'Too many requests.'}});
const authLimiter = rateLimit({windowMs:LOGIN_WINDOW_MS,limit:5,standardHeaders:'draft-8',legacyHeaders:false,message:{success:false,error:'AUTH_RATE_LIMITED',message:'5 login attempts are allowed per 10 minutes.'}});
const adminLimiter = rateLimit({windowMs:60*1000,limit:60,standardHeaders:'draft-8',legacyHeaders:false,message:{success:false,error:'ADMIN_RATE_LIMITED',message:'Too many admin requests.'}});
app.use(generalLimiter);

function fail(res,status,error,message,extra={}){return res.status(status).json({success:false,error,message,...extra});}
function safeEqual(a,b){const x=Buffer.from(String(a));const y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y);}
function randomId(bytes=16){return crypto.randomBytes(bytes).toString('hex');}
function sixDigitCode(v){return /^\d{6}$/.test(String(v||''));}
function safeId(v,label='id'){const x=String(v??'').trim();if(!x||x.length>220||/[\u0000-\u001F]/.test(x))throw new Error(`INVALID_${label.toUpperCase()}`);return x;}
function parseJsonEnv(name){const raw=process.env[name];if(!raw)return null;try{return JSON.parse(raw);}catch(_){try{return JSON.parse(Buffer.from(raw,'base64').toString('utf8'));}catch(__){return null;}}}
function hashSecret(value,salt=crypto.randomBytes(16).toString('hex')){return new Promise((resolve,reject)=>crypto.scrypt(String(value),salt,64,{N:16384,r:8,p:1},(e,d)=>e?reject(e):resolve(`${salt}:${d.toString('hex')}`)));}
function verifySecret(value,stored){return new Promise((resolve,reject)=>{const [salt,expected]=String(stored||'').split(':');if(!salt||!expected)return resolve(false);crypto.scrypt(String(value),salt,64,{N:16384,r:8,p:1},(e,d)=>{if(e)return reject(e);resolve(safeEqual(d.toString('hex'),expected));});});}
function codeLookup(code){if(!JWT_SECRET)throw new Error('API_JWT_SECRET_NOT_CONFIGURED');return crypto.createHmac('sha256',JWT_SECRET).update(`student-code:${code}`).digest('hex');}
function videoKey(){return crypto.createHash('sha256').update(String(JWT_SECRET)).digest();}
function videoPublicId(docId){
  const iv=crypto.createHmac('sha256',videoKey()).update(`iv:${docId}`).digest().subarray(0,12);
  const c=crypto.createCipheriv('aes-256-gcm',videoKey(),iv);const body=Buffer.concat([c.update(String(docId),'utf8'),c.final()]);const tag=c.getAuthTag();
  return 'vid_'+Buffer.concat([iv,tag,body]).toString('base64url');
}
function videoDocIdFromPublicId(publicId){
  try{const raw=Buffer.from(String(publicId).replace(/^vid_/,''),'base64url');if(raw.length<28)return null;const iv=raw.subarray(0,12),tag=raw.subarray(12,28),body=raw.subarray(28);const d=crypto.createDecipheriv('aes-256-gcm',videoKey(),iv);d.setAuthTag(tag);return d.update(body,'','utf8')+d.final('utf8');}catch(_){return null;}
}
function b64(v){return Buffer.from(v).toString('base64url');}
function signToken(payload){const h=b64(JSON.stringify({alg:'HS256',typ:'JWT'}));const p=b64(JSON.stringify(payload));const s=crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${p}`).digest('base64url');return `${h}.${p}.${s}`;}
function verifyToken(token){const a=String(token||'').split('.');if(a.length!==3||!JWT_SECRET)return null;const [h,p,s]=a;const expected=crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${p}`).digest('base64url');if(!safeEqual(s,expected))return null;try{const x=JSON.parse(Buffer.from(p,'base64url').toString());if(!x.exp||x.exp<=Math.floor(Date.now()/1000))return null;return x;}catch(_){return null;}}
function bearer(req){const h=String(req.headers.authorization||'');return h.startsWith('Bearer ')?h.slice(7).trim():'';}
function clientIp(req){return String(req.ip||req.headers['x-forwarded-for']||'unknown').split(',')[0].trim();}
function hashIp(ip){return crypto.createHmac('sha256',JWT_SECRET).update(String(ip)).digest('hex').slice(0,24);}
function serialize(v){if(v===null||v===undefined)return v;if(v?.toDate instanceof Function)return v.toDate().toISOString();if(Array.isArray(v))return v.map(serialize);if(typeof v==='object'){const o={};for(const[k,x]of Object.entries(v))o[k]=serialize(x);return o;}return v;}

// ---------------- Firebase ----------------
let db=null; let firebaseMode=null;
function initFirebase(){
  const service=parseJsonEnv('FIREBASE_ADMIN_SERVICE_ACCOUNT_JSON');
  if(service?.type==='service_account'&&service.private_key&&service.client_email){
    try{if(!admin.apps.length)admin.initializeApp({credential:admin.credential.cert(service),databaseURL:RTDB_URL||undefined});db=admin.firestore();firebaseMode='admin';console.log('Firebase Admin connected');return;}catch(e){console.error('Firebase init failed:',e.message);}
  }
}
initFirebase();
function needDb(res){if(db)return true;fail(res,503,'FIREBASE_NOT_CONFIGURED','Firebase Admin is not configured.');return false;}
async function rtdb(path,options={}){
  if(firebaseMode==='admin'&&admin.apps.length){
    const raw=String(path);const [pathname,queryString='']=raw.split('?');const clean=pathname.replace(/\.json$/,'').replace(/^\/+|\/+$/g,'');let ref=admin.database().ref(clean.split('/').filter(Boolean).map(decodeURIComponent).join('/'));
    const params=new URLSearchParams(queryString);if(params.has('orderBy'))ref=ref.orderByChild(JSON.parse(params.get('orderBy')));if(params.has('equalTo'))ref=ref.equalTo(JSON.parse(params.get('equalTo')));if(params.has('limitToFirst'))ref=ref.limitToFirst(Number(params.get('limitToFirst')));
    const method=(options.method||'GET').toUpperCase();if(method==='GET'){const snap=await ref.once('value');return snap.val();}if(method==='POST'){const pushed=ref.push();await pushed.set(options.body);return{name:pushed.key};}if(method==='PATCH'){await ref.update(options.body||{});return null;}if(method==='PUT'){await ref.set(options.body);return null;}if(method==='DELETE'){await ref.remove();return null;}throw new Error(`RTDB_METHOD_${method}`);
  }
  if(!RTDB_URL)throw new Error('RTDB_NOT_CONFIGURED');
  const raw=String(path);const [pathname,query='']=raw.split('?');const url=`${RTDB_URL}${pathname.startsWith('/')?'':'/'}${pathname.endsWith('.json')?pathname:`${pathname}.json`}${query?'?'+query:''}`;const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),8000);
  try{const response=await fetch(url,{method:options.method||'GET',headers:{'Content-Type':'application/json'},body:options.body===undefined?undefined:JSON.stringify(options.body),signal:controller.signal});const text=await response.text();let data=null;try{data=text?JSON.parse(text):null;}catch(_){data=text;}if(!response.ok){const e=new Error(`RTDB_${response.status}`);e.status=response.status;e.body=data;throw e;}return data;}finally{clearTimeout(timer);}
}
async function getStudent(id){return await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`);}
async function getStudentByLookup(lookup){const path=`${encodeURIComponent(STUDENTS_PATH)}.json?orderBy=%22codeLookup%22&equalTo=${encodeURIComponent(JSON.stringify(lookup))}&limitToFirst=1`;const data=await rtdb(path);if(!data||typeof data!=='object')return null;const e=Object.entries(data)[0];return e?{id:e[0],data:e[1]||{}}:null;}

// ---------------- Auth / device enforcement ----------------
async function loadAndValidateStudent(req,claims){
  if(!claims||claims.role!=='student'||!claims.sub)return null;
  const d=await getStudent(claims.sub);if(!d)return null;
  if(d.status==='disabled'||d.status==='deleted')return null;
  if(Number(d.expiresAt||0)<=Date.now())return null;
  const deviceId=String(claims.deviceId||'');if(!deviceId)return null;
  const device=d.devices?.[deviceId];if(!device||device.blocked===true)return null;
  device.lastSeenAt=Date.now();device.lastIpHash=hashIp(clientIp(req));
  try{await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(claims.sub)}/devices/${encodeURIComponent(deviceId)}.json`,{method:'PATCH',body:{lastSeenAt:device.lastSeenAt,lastIpHash:device.lastIpHash}});}catch(_){ }
  return {id:claims.sub,data:d,deviceId};
}
async function requireStudent(req,res,next){try{const p=verifyToken(bearer(req));const student=await loadAndValidateStudent(req,p);if(!student)return fail(res,401,'UNAUTHORIZED','Valid active student session required.');req.auth=p;req.student=student;next();}catch(e){console.error(e);fail(res,401,'UNAUTHORIZED','Valid active student session required.');}}
function requireAdmin(req,res,next){const p=verifyToken(bearer(req));if(!p||p.role!=='admin'||p.sub!=='admin')return fail(res,401,'ADMIN_UNAUTHORIZED','Valid admin Bearer token required.');req.auth=p;next();}

// ---------------- Login: exactly 5 attempts / 10 min per IP + device ----------------
app.post('/verify-pin',authLimiter,async(req,res)=>{
  try{
    if(!JWT_SECRET)return fail(res,503,'AUTH_NOT_CONFIGURED','API_JWT_SECRET is not configured.');
    const code=String(req.body?.pin||req.body?.code||'').trim();const deviceId=safeId(req.body?.deviceId,'device_id');
    if(!sixDigitCode(code))return fail(res,400,'INVALID_CODE','Student code must contain exactly 6 digits.');
    const lookup=codeLookup(code);const found=await getStudentByLookup(lookup);if(!found)return fail(res,401,'INVALID_CREDENTIALS','Invalid or expired code.');
    const d=found.data;const expires=Number(d.expiresAt||0);const valid=d.status!=='disabled'&&d.status!=='deleted'&&expires>Date.now()&&await verifySecret(code,d.codeHash);if(!valid)return fail(res,401,'INVALID_CREDENTIALS','Invalid or expired code.');
    const devices=d.devices&&typeof d.devices==='object'?d.devices:{};const existing=devices[deviceId];const activeIds=Object.entries(devices).filter(([_,v])=>v&&v.blocked!==true).map(([id])=>id);const deviceLimit=Math.max(1,Number(d.deviceLimit||MAX_DEVICES_DEFAULT));
    if(!existing && activeIds.length>=deviceLimit)return fail(res,403,'DEVICE_LIMIT_REACHED','This student has reached the allowed device limit.',{deviceLimit});
    const now=Date.now();
    await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(found.id)}/devices/${encodeURIComponent(deviceId)}.json`,{method:'PUT',body:{blocked:false,firstSeenAt:existing?.firstSeenAt||now,lastSeenAt:now,lastIpHash:hashIp(clientIp(req)),userAgent:String(req.body?.userAgent||'').slice(0,500)}});
    const sec=Math.floor(now/1000);const token=signToken({sub:found.id,role:'student',deviceId,iat:sec,exp:sec+ACCESS_TTL_SECONDS,jti:randomId(12)});
    await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(found.id)}.json`,{method:'PATCH',body:{lastLoginAt:now,lastLoginDeviceId:deviceId}});
    return res.json({success:true,sessionToken:token,accessToken:token,expiresIn:ACCESS_TTL_SECONDS,studentId:found.id,studentName:d.name||'',student:{id:found.id,name:d.name||'',status:d.status||'active',expiresAt:new Date(expires).toISOString(),deviceLimit,deviceId}});
  }catch(e){console.error('verify-pin',e);return fail(res,500,'LOGIN_FAILED','Login failed.');}
});
app.post('/api/auth/login',authLimiter,async(req,res)=>{req.body={...(req.body||{}),pin:req.body?.code||req.body?.pin,deviceId:req.body?.deviceId||`dev_${randomId(12)}`};return app._router.handle(Object.assign(req,{url:'/verify-pin',originalUrl:'/verify-pin'}),res,()=>{});});

// ---------------- Session config ----------------
app.get('/get-config',requireStudent,async(req,res)=>res.json({success:true,config:{studentId:req.student.id,name:req.student.data.name||'',section:req.student.data.section||'all',status:req.student.data.status||'active',expiresAt:req.student.data.expiresAt||null,deviceLimit:Number(req.student.data.deviceLimit||1),deviceId:req.student.deviceId}}));
app.get('/api/auth/me',requireStudent,async(req,res)=>res.json({success:true,student:{id:req.student.id,name:req.student.data.name||'',status:req.student.data.status||'active',expiresAt:req.student.data.expiresAt||null,deviceLimit:Number(req.student.data.deviceLimit||1),deviceId:req.student.deviceId}}));

// ---------------- Content sanitization ----------------
function sanitizeContentItem(doc){
  const data=serialize(doc.data()||{});const type=String(data.type||'').toLowerCase();const out={...data};
  const sensitiveKeys=['value','url','link','src','embedUrl','embed_url','downloadUrl','download_url','fileUrl','file_url','sourceUrl','source_url'];
  const sensitive=type==='video'||type==='youtube'||type==='pdf'||type==='drive'||type==='link';
  if(sensitive){for(const k of sensitiveKeys)delete out[k];out.resourceId=doc.id;out.videoId=(type==='video'||type==='youtube')?videoPublicId(doc.id):undefined;}
  return {id:doc.id,data:out};
}
app.get('/api/content',requireStudent,async(req,res)=>{
  if(!needDb(res))return;try{
    const ids=String(req.query.parentIds??req.query.parentId??'root').split(',').map(x=>x.trim()).filter(Boolean).slice(0,50);const unique=[...new Set(ids)];let docs=[];
    for(const parentId of unique){const snap=await db.collection('content').where('parentId','==',parentId).get();snap.forEach(doc=>docs.push(sanitizeContentItem(doc)));}
    const seen=new Set();docs=docs.filter(x=>!seen.has(x.id)&&seen.add(x.id));docs.sort((a,b)=>(Number(a.data.order)||0)-(Number(b.data.order)||0));
    res.set('Cache-Control','private,no-store');res.json({success:true,source:'server',collection:'content',parentIds:unique,count:docs.length,items:docs});
  }catch(e){console.error(e);fail(res,500,'CONTENT_READ_FAILED','Unable to read content.');}
});
app.get('/api/content/doc/:id',requireStudent,async(req,res)=>{if(!needDb(res))return;try{const id=safeId(req.params.id);const snap=await db.collection('content').doc(id).get();if(!snap.exists)return fail(res,404,'CONTENT_NOT_FOUND','Document not found.');res.set('Cache-Control','private,no-store');res.json({success:true,item:sanitizeContentItem(snap)});}catch(e){fail(res,500,'CONTENT_DOCUMENT_READ_FAILED','Unable to read document.');}});

// ---------------- Secure video tokens + origin relay ----------------
function findVideoDocIdByPublicId(videoId){
  const prefix='vid_';if(!String(videoId).startsWith(prefix))return null;
  // Public id is HMAC(docId), so it cannot be reversed. Resolve by query only when needed.
  return null;
}
async function findVideoByPublicId(videoId){
  if(!needDbLike())return null;
  const docId=videoDocIdFromPublicId(videoId);if(!docId)return null;
  const doc=await db.collection('content').doc(docId).get();if(!doc.exists)return null;
  const type=String(doc.data()?.type||'').toLowerCase();if(type!=='video'&&type!=='youtube')return null;
  return {id:doc.id,data:doc.data()||{}};
}
function needDbLike(){return Boolean(db);}
app.post('/api/video/token',requireStudent,async(req,res)=>{
  if(!needDb(res))return;try{
    const publicId=safeId(req.body?.videoId,'video_id');const found=await findVideoByPublicId(publicId);if(!found)return fail(res,404,'VIDEO_NOT_FOUND','Video not found.');
    const type=String(found.data.type||'').toLowerCase();if(type!=='video'&&type!=='youtube')return fail(res,400,'NOT_A_VIDEO','Item is not a video.');
    let source=String(found.data.value||found.data.url||found.data.link||found.data.src||'').trim();source=await resolveBunnySource(source);if(!/^https?:\/\//i.test(source))return fail(res,404,'VIDEO_SOURCE_MISSING','Video source is not configured.');
    const now=Math.floor(Date.now()/1000);const playToken=signToken({sub:req.student.id,role:'video',deviceId:req.student.deviceId,vid:publicId,iat:now,exp:now+VIDEO_TOKEN_TTL_SECONDS,jti:randomId(12)});
    res.set('Cache-Control','no-store');res.json({success:true,videoId:publicId,playToken,expiresAt:new Date((now+VIDEO_TOKEN_TTL_SECONDS)*1000).toISOString(),expiresIn:VIDEO_TOKEN_TTL_SECONDS});
  }catch(e){console.error(e);fail(res,500,'VIDEO_TOKEN_FAILED','Unable to create video token.');}
});

function parseBunnyEmbed(url){
  try{const u=new URL(String(url));if(!/^(player\.)?mediadelivery\.net$/i.test(u.hostname))return null;const p=u.pathname.split('/').filter(Boolean);const i=p.findIndex(x=>/^(embed|play)$/i.test(x));if(i>=0&&p[i+1]&&p[i+2])return {library:p[i+1],guid:p[i+2]};}catch(_){ }return null;
}
async function resolveBunnySource(raw){
  const parsed=parseBunnyEmbed(raw);if(!parsed||!BUNNY_API_KEY)return raw;
  const r=await fetch(`${BUNNY_API_BASE}/${encodeURIComponent(parsed.library)}/videos/${encodeURIComponent(parsed.guid)}`,{headers:{AccessKey:BUNNY_API_KEY,Accept:'application/json'}});
  if(!r.ok)return raw;const d=await r.json();
  // Prefer a concrete downloadable MP4 if Bunny exposes one; otherwise use the reported storage/path URL.
  const candidates=[d?.storageSize&&d?.guid?`https://${parsed.library}.b-cdn.net/${d.guid}/play_720p.mp4`:null,d?.videoUrl,d?.sourceUrl,d?.url].filter(Boolean);
  return candidates[0]||raw;
}

function contentTypeForUrl(url){const p=String(url).split('?')[0].toLowerCase();if(p.endsWith('.m3u8'))return 'application/vnd.apple.mpegurl';if(p.endsWith('.webm'))return 'video/webm';if(p.endsWith('.ogg'))return 'video/ogg';return 'video/mp4';}
app.get('/api/video/stream/:videoId',async(req,res)=>{
  try{
    const token=verifyToken(req.query.token);if(!token||token.role!=='video'||token.vid!==String(req.params.videoId))return fail(res,401,'VIDEO_TOKEN_INVALID','Valid video token required.');
    if(String(req.headers['x-device-id']||'') && String(req.headers['x-device-id'])!==String(token.deviceId))return fail(res,401,'DEVICE_MISMATCH','Device mismatch.');
    const student=await getStudent(token.sub);if(!student||student.status==='disabled'||student.status==='deleted'||Number(student.expiresAt||0)<=Date.now())return fail(res,401,'SESSION_INVALID','Student session is no longer active.');
    const dev=student.devices?.[token.deviceId];if(!dev||dev.blocked===true)return fail(res,403,'DEVICE_BLOCKED','Device is blocked.');
    if(!needDb(res))return;const found=await findVideoByPublicId(String(req.params.videoId));if(!found)return fail(res,404,'VIDEO_NOT_FOUND','Video not found.');
    let source=String(found.data.value||found.data.url||found.data.link||found.data.src||'').trim();source=await resolveBunnySource(source);if(!/^https?:\/\//i.test(source))return fail(res,404,'VIDEO_SOURCE_MISSING','Video source is not configured.');
    const headers={};if(req.headers.range)headers.Range=req.headers.range;
    const upstream=await fetch(source,{headers,redirect:'manual'});
    if([301,302,303,307,308].includes(upstream.status))return fail(res,502,'ORIGIN_REDIRECT_NOT_ALLOWED','The upstream media must be a direct media URL, not a redirect.');
    if(!upstream.ok&&upstream.status!==206)return fail(res,502,'ORIGIN_FETCH_FAILED',`Upstream media returned HTTP ${upstream.status}.`);
    const ct=upstream.headers.get('content-type')||contentTypeForUrl(source);res.status(upstream.status);res.set('Content-Type',ct);res.set('Cache-Control','private,no-store');res.set('Accept-Ranges',upstream.headers.get('accept-ranges')||'bytes');
    for(const h of ['content-length','content-range']){const v=upstream.headers.get(h);if(v)res.set(h==='content-length'?'Content-Length':'Content-Range',v);}
    if(upstream.body){const reader=upstream.body.getReader();req.on('close',()=>{try{reader.cancel();}catch(_){}});while(true){const {done,value}=await reader.read();if(done)break;if(!res.write(Buffer.from(value)))await new Promise(resolve=>res.once('drain',resolve));}res.end();}else res.end(Buffer.from(await upstream.arrayBuffer()));
  }catch(e){console.error('video stream',e);if(!res.headersSent)fail(res,502,'VIDEO_STREAM_FAILED','Unable to stream video.');else res.destroy();}
});

// ---------------- Admin ----------------
app.post('/api/admin/login',adminLimiter,async(req,res)=>{if(!JWT_SECRET||!ADMIN_USERNAME||!ADMIN_PASSWORD)return fail(res,503,'ADMIN_AUTH_NOT_CONFIGURED','Admin authentication is not configured.');const username=String(req.body?.username||'');const password=String(req.body?.password||'');if(!safeEqual(username,ADMIN_USERNAME)||!safeEqual(password,ADMIN_PASSWORD))return fail(res,401,'INVALID_ADMIN_CREDENTIALS','Invalid admin credentials.');const now=Math.floor(Date.now()/1000);const token=signToken({sub:'admin',role:'admin',iat:now,exp:now+ACCESS_TTL_SECONDS,jti:randomId(12)});res.json({success:true,accessToken:token,expiresIn:ACCESS_TTL_SECONDS});});
app.get('/api/admin/students',requireAdmin,async(req,res)=>{try{const data=await rtdb(`${encodeURIComponent(STUDENTS_PATH)}.json`);const students=Object.entries(data||{}).map(([id,d])=>({id,name:d?.name||'',status:d?.status||'active',durationDays:d?.durationDays||null,createdAt:d?.createdAt||null,expiresAt:d?.expiresAt||null,lastLoginAt:d?.lastLoginAt||null,deviceLimit:Number(d?.deviceLimit||1),deviceCount:Object.keys(d?.devices||{}).length,devices:Object.entries(d?.devices||{}).map(([deviceId,v])=>({deviceId,...v}))}));students.sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));res.json({success:true,count:students.length,students:students.slice(0,2000)});}catch(e){console.error(e);fail(res,500,'STUDENTS_READ_FAILED','Unable to list students.');}});
app.get('/api/admin/stats',requireAdmin,async(req,res)=>{try{const data=await rtdb(`${encodeURIComponent(STUDENTS_PATH)}.json`);const arr=Object.values(data||{});const now=Date.now();const stats={total:arr.length,active:arr.filter(d=>d?.status==='active'&&Number(d?.expiresAt||0)>now).length,disabled:arr.filter(d=>d?.status==='disabled').length,expired:arr.filter(d=>d?.status==='active'&&Number(d?.expiresAt||0)<=now).length,totalDevices:arr.reduce((n,d)=>n+Object.keys(d?.devices||{}).length,0),blockedDevices:arr.reduce((n,d)=>n+Object.values(d?.devices||{}).filter(x=>x?.blocked===true).length,0),logins24h:arr.filter(d=>Number(d?.lastLoginAt||0)>now-86400000).length};res.json({success:true,stats});}catch(e){fail(res,500,'STATS_FAILED','Unable to load stats.');}});
app.post('/api/admin/students',requireAdmin,async(req,res)=>{try{const name=String(req.body?.name||'').trim();const durationDays=Number(req.body?.durationDays);const deviceLimit=Number(req.body?.deviceLimit||1);if(!name||name.length>120)return fail(res,400,'INVALID_NAME','Invalid name.');if(!Number.isInteger(durationDays)||durationDays<1||durationDays>3650)return fail(res,400,'INVALID_DURATION','durationDays must be 1..3650.');if(!Number.isInteger(deviceLimit)||deviceLimit<1||deviceLimit>50)return fail(res,400,'INVALID_DEVICE_LIMIT','deviceLimit must be 1..50.');let code='',lookup='',existing=null;for(let attempt=0;attempt<50;attempt++){code=String(crypto.randomInt(0,1000000)).padStart(6,'0');lookup=codeLookup(code);existing=await getStudentByLookup(lookup);if(!existing||existing.data?.status==='deleted')break;}if(existing&&existing.data?.status!=='deleted')return fail(res,503,'CODE_GENERATION_FAILED','Unable to generate a unique student code.');const now=Date.now();const expiresAt=now+durationDays*86400000;const body={name,codeHash:await hashSecret(code),codeLookup:lookup,status:'active',durationDays,deviceLimit,devices:{},createdAt:now,expiresAt,lastLoginAt:null};const created=await rtdb(`${encodeURIComponent(STUDENTS_PATH)}.json`,{method:'POST',body});if(!created?.name)throw new Error('RTDB_CREATE_FAILED');res.status(201).json({success:true,student:{id:created.name,name,code,durationDays,deviceLimit,status:'active',createdAt:new Date(now).toISOString(),expiresAt:new Date(expiresAt).toISOString()}});}catch(e){console.error(e);fail(res,500,'STUDENT_CREATE_FAILED','Unable to create student.');}});
app.patch('/api/admin/students/:id',requireAdmin,async(req,res)=>{try{const id=safeId(req.params.id);const current=await getStudent(id);if(!current)return fail(res,404,'STUDENT_NOT_FOUND','Student not found.');const patch={};if(req.body?.name!==undefined){const name=String(req.body.name).trim();if(!name||name.length>120)return fail(res,400,'INVALID_NAME','Invalid name.');patch.name=name;}if(req.body?.status!==undefined){const status=String(req.body.status);if(!['active','disabled','deleted'].includes(status))return fail(res,400,'INVALID_STATUS','Invalid status.');patch.status=status;}if(req.body?.durationDays!==undefined){const days=Number(req.body.durationDays);if(!Number.isInteger(days)||days<1||days>3650)return fail(res,400,'INVALID_DURATION','Invalid duration.');patch.durationDays=days;patch.expiresAt=Date.now()+days*86400000;}if(req.body?.deviceLimit!==undefined){const n=Number(req.body.deviceLimit);if(!Number.isInteger(n)||n<1||n>50)return fail(res,400,'INVALID_DEVICE_LIMIT','Invalid deviceLimit.');patch.deviceLimit=n;}if(req.body?.newCode!==undefined){const code=String(req.body.newCode).trim();if(!sixDigitCode(code))return fail(res,400,'INVALID_CODE','newCode must be exactly 6 digits.');const other=await getStudentByLookup(codeLookup(code));if(other&&other.id!==id&&other.data?.status!=='deleted')return fail(res,409,'CODE_IN_USE','That code is already in use.');patch.codeHash=await hashSecret(code);patch.codeLookup=codeLookup(code);}if(!Object.keys(patch).length)return fail(res,400,'NOTHING_TO_UPDATE','No valid fields supplied.');patch.updatedAt=Date.now();await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`,{method:'PATCH',body:patch});res.json({success:true,id,updated:true});}catch(e){console.error(e);fail(res,500,'STUDENT_UPDATE_FAILED','Unable to update student.');}});
app.delete('/api/admin/students/:id',requireAdmin,async(req,res)=>{try{const id=safeId(req.params.id);const current=await getStudent(id);if(!current)return fail(res,404,'STUDENT_NOT_FOUND','Student not found.');await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`,{method:'PATCH',body:{status:'deleted',deletedAt:Date.now(),updatedAt:Date.now()}});res.json({success:true,id,deleted:true});}catch(e){fail(res,500,'STUDENT_DELETE_FAILED','Unable to delete student.');}});
app.patch('/api/admin/students/:id/devices/:deviceId',requireAdmin,async(req,res)=>{try{const id=safeId(req.params.id),deviceId=safeId(req.params.deviceId);const current=await getStudent(id);if(!current)return fail(res,404,'STUDENT_NOT_FOUND','Student not found.');const exists=current.devices?.[deviceId];if(!exists)return fail(res,404,'DEVICE_NOT_FOUND','Device not found.');const blocked=Boolean(req.body?.blocked);await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceId)}.json`,{method:'PATCH',body:{blocked,updatedAt:Date.now()}});res.json({success:true,blocked});}catch(e){fail(res,500,'DEVICE_UPDATE_FAILED','Unable to update device.');}});
app.delete('/api/admin/students/:id/devices/:deviceId',requireAdmin,async(req,res)=>{try{const id=safeId(req.params.id),deviceId=safeId(req.params.deviceId);const current=await getStudent(id);if(!current)return fail(res,404,'STUDENT_NOT_FOUND','Student not found.');await rtdb(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceId)}.json`,{method:'DELETE'});res.json({success:true,removed:true});}catch(e){fail(res,500,'DEVICE_DELETE_FAILED','Unable to remove device.');}});

app.get('/',(req,res)=>res.json({success:true,name:'Durosak Plus API V6',security:'server-mediated-content-and-video',videoTokenTtlSeconds:VIDEO_TOKEN_TTL_SECONDS}));
app.get('/health',(req,res)=>res.json({success:true,firestoreConfigured:Boolean(db),firestoreMode:firebaseMode,rtdbConfigured:Boolean(RTDB_URL)||firebaseMode==='admin',time:new Date().toISOString()}));
app.use((req,res)=>fail(res,404,'NOT_FOUND','Endpoint not found.'));
app.use((err,req,res,next)=>{console.error(err);if(err?.message==='CORS_ORIGIN_NOT_ALLOWED')return fail(res,403,'CORS_BLOCKED','Origin is not allowed.');return fail(res,500,'INTERNAL_ERROR','Internal server error.');});
if(!JWT_SECRET)console.warn('WARNING: API_JWT_SECRET missing.');
if(!ADMIN_USERNAME||!ADMIN_PASSWORD)console.warn('WARNING: ADMIN_USERNAME/ADMIN_PASSWORD missing.');
app.listen(PORT,()=>console.log(`Durosak Plus API V6 listening on ${PORT}`));
