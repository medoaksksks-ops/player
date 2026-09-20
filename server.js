// Durosak Plus API V3
// Firestore = educational content
// Firebase Realtime Database = student accounts
// All private API routes require a short-lived Bearer token.
// Admin credentials are NEVER hard-coded; configure them in Railway variables.

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
const RTDB_URL = String(process.env.FIREBASE_RTDB_URL || 'https://english-73376-default-rtdb.firebaseio.com').replace(/\/$/, '');
// Student accounts live ONLY under this RTDB node. Firebase creates it automatically on first student creation.
const STUDENTS_PATH = 'Durosak Student';
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
const ACCESS_TTL_SECONDS = Math.min(Math.max(Number(process.env.ACCESS_TTL_SECONDS) || 3600, 300), 86400);
const VIDEO_TOKEN_TTL_SECONDS = Math.min(Math.max(Number(process.env.VIDEO_TOKEN_TTL_SECONDS) || 900, 60), 3600);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin(origin, cb) {
    if (!origin || origin === 'null' || !ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS_ORIGIN_NOT_ALLOWED'));
  },
  methods: ['GET','POST','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '256kb' }));

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { success:false, error:'RATE_LIMITED', message:'Too many requests.' }
});
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 15,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { success:false, error:'AUTH_RATE_LIMITED', message:'Too many authentication attempts.' }
});
app.use(generalLimiter);

function fail(res, status, error, message, extra = {}) { return res.status(status).json({ success:false, error, message, ...extra }); }
function safeEqual(a,b) { const x=Buffer.from(String(a)); const y=Buffer.from(String(b)); return x.length===y.length && crypto.timingSafeEqual(x,y); }
function randomId(bytes=16) { return crypto.randomBytes(bytes).toString('hex'); }
function sixDigitCode(v) { return /^\d{6}$/.test(String(v || '')); }
function safeId(v,label='id') { const x=String(v ?? '').trim(); if(!x || x.length>200 || /[\u0000-\u001F]/.test(x)) throw new Error(`INVALID_${label.toUpperCase()}`); return x; }
function parseJsonEnv(name) { const raw=process.env[name]; if(!raw) return null; try{return JSON.parse(raw);}catch(_){try{return JSON.parse(Buffer.from(raw,'base64').toString('utf8'));}catch(__){return null;}} }
function hashSecret(value,salt=crypto.randomBytes(16).toString('hex')) { return new Promise((resolve,reject)=>crypto.scrypt(String(value),salt,64,{N:16384,r:8,p:1},(e,d)=>e?reject(e):resolve(`${salt}:${d.toString('hex')}`))); }
function verifySecret(value,stored) { return new Promise((resolve,reject)=>{const [salt,expected]=String(stored||'').split(':'); if(!salt||!expected)return resolve(false); crypto.scrypt(String(value),salt,64,{N:16384,r:8,p:1},(e,d)=>{if(e)return reject(e);resolve(safeEqual(d.toString('hex'),expected));});}); }
function codeLookup(code) { if(!JWT_SECRET) throw new Error('API_JWT_SECRET_NOT_CONFIGURED'); return crypto.createHmac('sha256',JWT_SECRET).update(`student-code:${code}`).digest('hex'); }
function b64(v){return Buffer.from(v).toString('base64url');}
function signToken(payload){const h=b64(JSON.stringify({alg:'HS256',typ:'JWT'}));const p=b64(JSON.stringify(payload));const s=crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${p}`).digest('base64url');return `${h}.${p}.${s}`;}
function verifyToken(token){const a=String(token||'').split('.');if(a.length!==3||!JWT_SECRET)return null;const [h,p,s]=a;const expected=crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${p}`).digest('base64url');if(!safeEqual(s,expected))return null;try{const x=JSON.parse(Buffer.from(p,'base64url').toString());if(!x.exp||x.exp<=Math.floor(Date.now()/1000))return null;return x;}catch(_){return null;}}
function bearer(req){const h=String(req.headers.authorization||'');return h.startsWith('Bearer ')?h.slice(7).trim():'';}

// ---------------- Firebase / Firestore ----------------
let db=null; let firebaseMode=null;
function initFirebase(){
  const service=parseJsonEnv('FIREBASE_ADMIN_SERVICE_ACCOUNT_JSON');
  if(service?.type==='service_account' && service.private_key && service.client_email){
    try{if(!admin.apps.length)admin.initializeApp({credential:admin.credential.cert(service),databaseURL:RTDB_URL});db=admin.firestore();firebaseMode='admin';console.log('Firestore Admin + RTDB connected');return;}catch(e){console.error('Firestore init failed:',e.message);}
  }
  const web=parseJsonEnv('FIREBASE_SERVICE_ACCOUNT_JSON');
  if(web?.apiKey && web?.projectId){
    try{const fa=require('firebase/app');const fs=require('firebase/firestore');const client=fa.initializeApp(web);db=fs.getFirestore(client);firebaseMode='web';console.log('Firestore Web Config connected');}catch(e){console.error('Firestore Web init failed:',e.message);}
  }
}
initFirebase();
function needDb(res){if(db)return true;fail(res,503,'FIREBASE_NOT_CONFIGURED','Firestore is not configured.');return false;}
function contentQuery(parentId){if(firebaseMode==='web'){const fs=require('firebase/firestore');return fs.getDocs(fs.query(fs.collection(db,'content'),fs.where('parentId','==',parentId)));}return db.collection('content').where('parentId','==',parentId).get();}
function contentDoc(id){if(firebaseMode==='web'){const fs=require('firebase/firestore');return fs.getDoc(fs.doc(db,'content',id));}return db.collection('content').doc(id).get();}
function serialize(v){if(v===null||v===undefined)return v;if(v?.toDate instanceof Function)return v.toDate().toISOString();if(Array.isArray(v))return v.map(serialize);if(typeof v==='object'){const o={};for(const[k,x]of Object.entries(v))o[k]=serialize(x);return o;}return v;}
function docToItem(doc){return{id:doc.id,data:serialize(doc.data()||{})};}
function parseParentIds(v){const arr=Array.isArray(v)?v:[v];const out=[];for(const x of arr){if(x===undefined||x===null||x==='')continue;for(const p of String(x).split(',').map(s=>s.trim()).filter(Boolean))out.push(safeId(p,'parent_id'));}return [...new Set(out)];}

// ---------------- Firebase Realtime Database ----------------
// rtdb() normally appends .json; allow a full query path safely.
async function rtdbPath(path,options={}){
  // Prefer Firebase Admin SDK when the server has the service account.
  // This avoids depending on public RTDB rules for private student-account writes.
  if(firebaseMode==='admin' && admin.apps.length){
    const raw=String(path);
    const [pathname,queryString='']=raw.split('?');
    const clean=pathname.replace(/\.json$/,'').replace(/^\/+|\/+$/g,'');
    let ref=admin.database().ref(clean.split('/').filter(Boolean).map(decodeURIComponent).join('/'));
    const params=new URLSearchParams(queryString);
    if(params.has('orderBy')) ref=ref.orderByChild(JSON.parse(params.get('orderBy')));
    if(params.has('equalTo')) ref=ref.equalTo(JSON.parse(params.get('equalTo')));
    if(params.has('limitToFirst')) ref=ref.limitToFirst(Number(params.get('limitToFirst')));
    const method=(options.method||'GET').toUpperCase();
    if(method==='GET'){ const snap=await ref.once('value'); return snap.val(); }
    if(method==='POST'){ const pushed=ref.push(); await pushed.set(options.body); return {name:pushed.key}; }
    if(method==='PATCH'){ await ref.update(options.body||{}); return null; }
    if(method==='PUT'){ await ref.set(options.body); return null; }
    if(method==='DELETE'){ await ref.remove(); return null; }
    throw new Error(`RTDB_METHOD_${method}`);
  }
  const raw=String(path);
  const [pathname,query='']=raw.split('?');
  const slash=pathname.startsWith('/')?'':'/';
  const normalized=pathname.endsWith('.json')?pathname:`${pathname}.json`;
  const url=`${RTDB_URL}${slash}${normalized}${query?'?'+query:''}`;
  const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),8000);
  try{
    const response=await fetch(url,{method:options.method||'GET',headers:{'Content-Type':'application/json'},body:options.body===undefined?undefined:JSON.stringify(options.body),signal:controller.signal});
    const text=await response.text();let data=null;try{data=text?JSON.parse(text):null;}catch(_){data=text;}
    if(!response.ok){const e=new Error(`RTDB_${response.status}`);e.status=response.status;e.body=data;throw e;}
    return data;
  }finally{clearTimeout(timer);}
}
async function getStudentByLookup(lookup){const path=`${encodeURIComponent(STUDENTS_PATH)}.json?orderBy=%22codeLookup%22&equalTo=${encodeURIComponent(JSON.stringify(lookup))}&limitToFirst=1`;const data=await rtdbPath(path);if(!data||typeof data!=='object')return null;const e=Object.entries(data)[0];return e?{id:e[0],data:e[1]||{}}:null;}
async function getStudent(id){return await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`);}

// ---------------- Exact original-site Firestore filtering ----------------
function normalizeSection(v){
  const x=String(v??'').trim().toLowerCase().replace(/[أإآ]/g,'ا').replace(/ى/g,'ي').replace(/ة/g,'ه').replace(/ـ/g,'').replace(/\s+/g,' ');
  if(x.includes('ثانوي')||x.includes('ثانويه')) return 'secondary';
  if(x.includes('بكالوريا')||x.includes('باكلوريا')) return 'baccalaureate';
  if(x.includes('ازهر')) return 'azhar';
  return x || 'all';
}
function studentSection(data){ return normalizeSection(data?.mainSection ?? data?.studentSection ?? data?.sectionKey ?? data?.section ?? data?.schoolSection ?? data?.branch ?? 'all'); }
function contentAllowed(data, section){
  const s=normalizeSection(section);
  const i=normalizeSection(data?.mainSection ?? data?.studentSection ?? data?.sectionKey ?? data?.section ?? data?.schoolSection ?? data?.branch ?? 'all');
  return i==='all' || s==='all' || i===s;
}

// Short-lived video access token. It gates the server's video-source endpoint;
// the underlying CDN/Bunny URL is never stored in the browser as a permanent API secret.
function signVideoToken(studentId, contentId, section='all'){
  const now=Math.floor(Date.now()/1000);
  return signToken({sub:String(studentId),role:'video',aud:'video',contentId:String(contentId),section:normalizeSection(section),iat:now,exp:now+VIDEO_TOKEN_TTL_SECONDS,jti:randomId(12)});
}
function verifyVideoToken(token, contentId){
  const p=verifyToken(token);
  return p && p.role==='video' && p.aud==='video' && String(p.contentId)===String(contentId) ? p : null;
}

// ---------------- Authentication ----------------
function requireStudent(req,res,next){const p=verifyToken(bearer(req));if(!p||p.role!=='student'||!p.sub)return fail(res,401,'UNAUTHORIZED','Valid student Bearer token required.');req.auth=p;next();}
function requireAdmin(req,res,next){const p=verifyToken(bearer(req));if(!p||p.role!=='admin'||!p.sub)return fail(res,401,'ADMIN_UNAUTHORIZED','Valid admin Bearer token required.');req.auth=p;next();}

app.get('/',(req,res)=>res.json({success:true,name:'Durosak Plus API',security:'bearer-token-protected',firestore:firebaseMode,rtdb:true}));
app.get('/health',(req,res)=>res.json({success:true,firestoreConfigured:Boolean(db),firestoreMode:firebaseMode,rtdbConfigured:Boolean(RTDB_URL),time:new Date().toISOString()}));

// ---------------- Admin login ----------------
app.post('/api/admin/login',authLimiter,async(req,res)=>{
  if(!JWT_SECRET||!ADMIN_USERNAME||!ADMIN_PASSWORD)return fail(res,503,'ADMIN_AUTH_NOT_CONFIGURED','Admin authentication is not configured.');
  const username=String(req.body?.username||'');const password=String(req.body?.password||'');
  if(!safeEqual(username,ADMIN_USERNAME)||!safeEqual(password,ADMIN_PASSWORD))return fail(res,401,'INVALID_ADMIN_CREDENTIALS','Invalid admin credentials.');
  const now=Math.floor(Date.now()/1000);const token=signToken({sub:'admin',role:'admin',iat:now,exp:now+ACCESS_TTL_SECONDS,jti:randomId(12)});
  res.json({success:true,accessToken:token,expiresIn:ACCESS_TTL_SECONDS,admin:{username:ADMIN_USERNAME}});
});

// ---------------- Student login ----------------
app.post('/api/auth/login',authLimiter,async(req,res)=>{
  try{if(!JWT_SECRET)return fail(res,503,'AUTH_NOT_CONFIGURED','API_JWT_SECRET is not configured.');const code=String(req.body?.code||'').trim();if(!sixDigitCode(code))return fail(res,400,'INVALID_CODE','Student code must contain exactly 6 digits.');const lookup=codeLookup(code);const found=await getStudentByLookup(lookup);if(!found)return fail(res,401,'INVALID_CREDENTIALS','Invalid or expired code.');const d=found.data;const expires=Number(d.expiresAt||0);const valid=d.status!=='disabled'&&d.status!=='deleted'&&expires>Date.now()&&await verifySecret(code,d.codeHash);if(!valid)return fail(res,401,'INVALID_CREDENTIALS','Invalid or expired code.');const now=Math.floor(Date.now()/1000);const token=signToken({sub:found.id,role:'student',section:studentSection(d),iat:now,exp:now+ACCESS_TTL_SECONDS,jti:randomId(12)});await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(found.id)}.json`,{method:'PATCH',body:{lastLoginAt:Date.now()}});return res.json({success:true,accessToken:token,expiresIn:ACCESS_TTL_SECONDS,student:{id:found.id,name:d.name||'',status:d.status||'active',section:studentSection(d),expiresAt:new Date(expires).toISOString()}});}catch(e){console.error('student login',e);return fail(res,500,'LOGIN_FAILED','Login failed.');}
});

// ---------------- Protected Firestore content ----------------
app.get('/api/content',requireStudent,async(req,res)=>{if(!needDb(res))return;try{const ids=parseParentIds(req.query.parentId??req.query.parentIds);if(!ids.length)return fail(res,400,'PARENT_ID_REQUIRED','Pass parentId.');const section=req.auth.section||'all';const lists=await Promise.all(ids.map(async id=>(await contentQuery(id)).docs.map(docToItem)));const items=[];const seen=new Set();for(const list of lists)for(const x of list){if(seen.has(x.id))continue;if(!contentAllowed(x.data,section))continue;seen.add(x.id);items.push(x);}items.sort((a,b)=>(Number(a.data?.order)||0)-(Number(b.data?.order)||0));res.set('Cache-Control','private,no-store');res.json({success:true,source:'firestore',collection:'content',parentIds:ids,section,count:items.length,items});}catch(e){console.error(e);fail(res,500,'CONTENT_READ_FAILED','Unable to read content.');}});
app.get('/api/content/doc/:id',requireStudent,async(req,res)=>{if(!needDb(res))return;try{const id=safeId(req.params.id);const snap=await contentDoc(id);const exists=typeof snap.exists==='function'?snap.exists():Boolean(snap.exists);if(!exists)return fail(res,404,'CONTENT_NOT_FOUND','Document not found.');const item=docToItem(snap);if(!contentAllowed(item.data,req.auth.section||'all'))return fail(res,403,'CONTENT_NOT_ALLOWED','Content is not available for this student section.');res.set('Cache-Control','private,no-store');res.json({success:true,source:'firestore',collection:'content',item});}catch(e){fail(res,500,'CONTENT_DOCUMENT_READ_FAILED','Unable to read document.');}});
app.get('/api/content/children',requireStudent,async(req,res)=>{if(!needDb(res))return;try{const ids=parseParentIds(req.query.parentIds??req.query.parentId);if(!ids.length)return fail(res,400,'PARENT_IDS_REQUIRED','Pass parentIds.');const section=req.auth.section||'all';const lists=await Promise.all(ids.map(async id=>(await contentQuery(id)).docs.map(docToItem).then(a=>a.filter(x=>contentAllowed(x.data,section)))));const byParentId={};const items=[];ids.forEach((id,i)=>{byParentId[id]=lists[i];lists[i].forEach(x=>items.push({parentId:id,...x}));});items.sort((a,b)=>(Number(a.data?.order)||0)-(Number(b.data?.order)||0));res.json({success:true,parentIds:ids,count:items.length,byParentId,items});}catch(e){fail(res,500,'BATCH_READ_FAILED','Unable to read content.');}});

// ---------------- Protected video token ----------------
// Client asks for a short-lived token for a specific Firestore video document.
app.post('/api/video/token',requireStudent,async(req,res)=>{
  if(!needDb(res))return;
  try{
    const id=safeId(req.body?.contentId,'content_id');
    const snap=await contentDoc(id);
    const exists=typeof snap.exists==='function'?snap.exists():Boolean(snap.exists);
    if(!exists)return fail(res,404,'VIDEO_NOT_FOUND','Video document not found.');
    const data=snap.data()||{};
    const type=String(data.type||'').toLowerCase();
    if(type!=='video'&&type!=='youtube')return fail(res,400,'NOT_A_VIDEO','The requested content is not a video.');
    if(!contentAllowed(data,req.auth.section||'all'))return fail(res,403,'VIDEO_NOT_ALLOWED','Video is not available for this student section.');
    const accessToken=signVideoToken(req.auth.sub,id,req.auth.section||'all');
    res.set('Cache-Control','private,no-store');
    return res.json({success:true,accessToken,expiresIn:VIDEO_TOKEN_TTL_SECONDS,contentId:id});
  }catch(e){console.error('video token',e);return fail(res,500,'VIDEO_TOKEN_FAILED','Unable to create video token.');}
});

app.get('/api/video/source/:id',async(req,res)=>{
  if(!needDb(res))return;
  try{
    const id=safeId(req.params.id,'content_id');
    const token=String(req.headers['x-video-token']||req.query.token||'');
    const auth=verifyVideoToken(token,id);
    if(!auth)return fail(res,401,'VIDEO_TOKEN_INVALID','Valid video token required.');
    const snap=await contentDoc(id);
    const exists=typeof snap.exists==='function'?snap.exists():Boolean(snap.exists);
    if(!exists)return fail(res,404,'VIDEO_NOT_FOUND','Video document not found.');
    const data=snap.data()||{};
    if(!contentAllowed(data,auth.section||'all'))return fail(res,403,'VIDEO_NOT_ALLOWED','Video is not available for this student section.');
    const source=String(data.value||data.url||data.link||data.src||data.embedUrl||'').trim();
    if(!source)return fail(res,404,'VIDEO_SOURCE_MISSING','Video source is missing in Firestore.');
    res.set('Cache-Control','private,no-store');
    return res.json({success:true,contentId:id,type:String(data.type||''),title:String(data.displayName||data.title||''),source});
  }catch(e){console.error('video source',e);return fail(res,500,'VIDEO_SOURCE_FAILED','Unable to read video source.');}
});

// ---------------- Admin student management ----------------
app.get('/api/admin/students',requireAdmin,async(req,res)=>{try{const data=await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}.json`);const students=Object.entries(data||{}).map(([id,d])=>({id,name:d?.name||'',status:d?.status||'active',durationDays:d?.durationDays||null,createdAt:d?.createdAt||null,expiresAt:d?.expiresAt||null,lastLoginAt:d?.lastLoginAt||null}));students.sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));res.json({success:true,storage:'firebase-rtdb',node:STUDENTS_PATH,count:students.length,students:students.slice(0,1000)});}catch(e){console.error(e);fail(res,500,'STUDENTS_READ_FAILED','Unable to list students.');}});

app.post('/api/admin/students',requireAdmin,async(req,res)=>{
  try{
    const name=String(req.body?.name||'').trim();
    const durationDays=Number(req.body?.durationDays);
    if(!name||name.length>120)return fail(res,400,'INVALID_NAME','Invalid name.');
    if(!Number.isInteger(durationDays)||durationDays<1||durationDays>3650)return fail(res,400,'INVALID_DURATION','durationDays must be 1..3650.');

    // Generate the 6-digit student code on the server. The client never chooses it.
    let code='', lookup='', existing=null;
    for(let attempt=0;attempt<25;attempt++){
      code=String(crypto.randomInt(0,1000000)).padStart(6,'0');
      lookup=codeLookup(code);
      existing=await getStudentByLookup(lookup);
      if(!existing || existing.data?.status==='deleted')break;
    }
    if(existing && existing.data?.status!=='deleted')return fail(res,503,'CODE_GENERATION_FAILED','Unable to generate a unique student code. Try again.');

    const codeHash=await hashSecret(code);
    const now=Date.now();
    const expiresAt=now+durationDays*86400000;
    const body={name,codeHash,codeLookup:lookup,status:'active',durationDays,createdAt:now,expiresAt,lastLoginAt:null};
    const created=await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}.json`,{method:'POST',body});
    const id=created?.name;
    if(!id)throw new Error('RTDB_CREATE_FAILED');
    res.status(201).json({success:true,student:{id,name,code,durationDays,status:'active',createdAt:new Date(now).toISOString(),expiresAt:new Date(expiresAt).toISOString()}});
  }catch(e){console.error('student create',e);fail(res,500,'STUDENT_CREATE_FAILED',e?.body?.error||e?.message||'Unable to create student.',{upstreamStatus:e?.status||null});}
});
app.patch('/api/admin/students/:id',requireAdmin,async(req,res)=>{try{const id=safeId(req.params.id);const current=await getStudent(id);if(!current)return fail(res,404,'STUDENT_NOT_FOUND','Student not found.');const patch={};if(req.body?.name!==undefined){const name=String(req.body.name).trim();if(!name||name.length>120)return fail(res,400,'INVALID_NAME','Invalid name.');patch.name=name;}if(req.body?.status!==undefined){const status=String(req.body.status);if(!['active','disabled'].includes(status))return fail(res,400,'INVALID_STATUS','Status must be active or disabled.');patch.status=status;}if(req.body?.durationDays!==undefined){const days=Number(req.body.durationDays);if(!Number.isInteger(days)||days<1||days>3650)return fail(res,400,'INVALID_DURATION','Invalid duration.');patch.durationDays=days;patch.expiresAt=Date.now()+days*86400000;}if(!Object.keys(patch).length)return fail(res,400,'NOTHING_TO_UPDATE','No valid fields supplied.');patch.updatedAt=Date.now();await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`,{method:'PATCH',body:patch});res.json({success:true,id,updated:true});}catch(e){console.error(e);fail(res,500,'STUDENT_UPDATE_FAILED','Unable to update student.');}});

app.delete('/api/admin/students/:id',requireAdmin,async(req,res)=>{try{const id=safeId(req.params.id);const current=await getStudent(id);if(!current)return fail(res,404,'STUDENT_NOT_FOUND','Student not found.');await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`,{method:'PATCH',body:{status:'deleted',deletedAt:Date.now(),updatedAt:Date.now()}});res.json({success:true,id,deleted:true});}catch(e){fail(res,500,'STUDENT_DELETE_FAILED','Unable to delete student.');}});

app.use((req,res)=>fail(res,404,'NOT_FOUND','Endpoint not found.'));
app.use((err,req,res,next)=>{console.error(err);if(err?.message==='CORS_ORIGIN_NOT_ALLOWED')return fail(res,403,'CORS_BLOCKED','Origin is not allowed.');return fail(res,500,'INTERNAL_ERROR','Internal server error.');});

if(!JWT_SECRET)console.warn('WARNING: API_JWT_SECRET missing.');
if(!ADMIN_USERNAME||!ADMIN_PASSWORD)console.warn('WARNING: ADMIN_USERNAME/ADMIN_PASSWORD missing.');
app.listen(PORT,()=>console.log(`Durosak Plus API listening on ${PORT}`));
