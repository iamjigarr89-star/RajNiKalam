require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { neon } = require('@neondatabase/serverless');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const VERCEL = Boolean(process.env.VERCEL);
const sql = process.env.DATABASE_URL ? neon(process.env.DATABASE_URL) : null;
const SECTIONS = ['home1','articles','gazal','kavita','chand','navalkatha'];

if (process.env.NODE_ENV === 'production' && (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32)) {
  throw new Error('JWT_SECRET must be at least 32 characters in production.');
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use('/api/', rateLimit({ windowMs: 15*60*1000, limit: 300, standardHeaders: 'draft-8', legacyHeaders: false }));

const authLimit = rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
let ready;

const text = (v, n=10000) => String(v ?? '').trim().slice(0,n);
const email = v => text(v,320).toLowerCase();
const today = () => new Date().toLocaleDateString('gu-IN',{year:'numeric',month:'long',day:'numeric'});
const userView = u => ({id:Number(u.id),name:u.name,email:u.email,role:u.role});
const tokenFor = u => jwt.sign(userView(u), process.env.JWT_SECRET, {expiresIn:'7d'});
const authToken = req => String(req.headers.authorization||'').replace(/^Bearer\s+/i,'').trim();

async function dbInit(){
  if(!sql) throw new Error('DATABASE_URL is not configured');
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS posts (
      id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, text TEXT NOT NULL, date_text TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'publish', pinned BOOLEAN NOT NULL DEFAULT FALSE, likes INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS comments (
      id BIGSERIAL PRIMARY KEY, post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,
      author TEXT NOT NULL, text TEXT NOT NULL, reply TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS likes (
      id BIGSERIAL PRIMARY KEY, post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,
      actor_key TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(post_id,actor_key)
    );
    CREATE TABLE IF NOT EXISTS section_likes (
      id BIGSERIAL PRIMARY KEY, section_key TEXT NOT NULL, actor_key TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(section_key,actor_key)
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value JSONB NOT NULL);
  `;

  const defaults={
    home1:{title:'શૈક્ષણિક અને સાહિત્યિક સંસ્કારો',content:'રાજ ની કલમ પર આપનું હાર્દિક સ્વાગત છે. શિક્ષણ અને સાહિત્ય માનવજીવનના સર્વાંગી વિકાસ માટે અત્યંત જરૂરી છે.',extraBoxes:[]},
    articles:{title:'લેખ',content:'ગુજરાતી ભાષા, શિક્ષણ, જીવનમૂલ્યો અને જ્ઞાનવિષયક ઉપયોગી લેખો અહીં વાંચો.',extraBoxes:[]},
    gazal:{title:'ગઝલ',content:'ગુજરાતી ગઝલના ભાવ, શબ્દ અને વિચાર સાથેનું વાંચન.',extraBoxes:[]},
    kavita:{title:'કવિતા',content:'કાવ્યપ્રેમીઓ માટે પસંદગીની ગુજરાતી કવિતાઓ અને સર્જનાત્મક લેખન.',extraBoxes:[]},
    chand:{title:'છંદ',content:'ગુજરાતી છંદ અને કાવ્યરચનાની સમજ માટે ઉપયોગી સામગ્રી.',extraBoxes:[]},
    navalkatha:{title:'નવલકથા',content:'નવલકથા અને વાર્તાસાહિત્યના રસપ્રદ અંશોનું વાંચન.',extraBoxes:[]}
  };
  for(const k of SECTIONS) await sql`INSERT INTO settings(key,value) VALUES(${`section:${k}`},${JSON.stringify(defaults[k])}::jsonb) ON CONFLICT(key) DO NOTHING`;
  await sql`INSERT INTO settings(key,value) VALUES('socialLinks',${JSON.stringify({instagram:'',facebook:'',youtube:'',twitter:'',whatsapp:''})}::jsonb) ON CONFLICT(key) DO NOTHING`;

  const count=await sql`SELECT COUNT(*)::int AS count FROM posts`;
  if(Number(count[0].count)===0) await sql`INSERT INTO posts(title,text,date_text,status,pinned) VALUES(${'રાજ ની કલમ પર આપનું હાર્દિક સ્વાગત'},${'શિક્ષણ, સાહિત્ય અને સર્જનાત્મક વાંચન માટે રાજ ની કલમ સાથે જોડાયેલા રહો. નવી પોસ્ટ માટે નિયમિત મુલાકાત લો.'},${today()},'publish',true)`;

  if(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
    const e=email(process.env.ADMIN_EMAIL);
    const found=await sql`SELECT id FROM users WHERE email=${e} LIMIT 1`;
    if(!found.length){
      const hash=await bcrypt.hash(String(process.env.ADMIN_PASSWORD),12);
      await sql`INSERT INTO users(name,email,password_hash,role) VALUES(${'Administrator'},${e},${hash},${'admin'})`;
    }
  }
}
function ensureDb(){ if(!ready) ready=dbInit().catch(e=>{ready=null;throw e}); return ready; }
app.use('/api/', async (req,res,next)=>{
  if(!sql) return res.status(503).json({error:'DATABASE_URL is not configured. Connect Neon Postgres in Vercel.'});
  try{await ensureDb();next()}catch(e){console.error(e);res.status(503).json({error:'Database initialization failed'})}
});

function requireAuth(req,res,next){
  const t=authToken(req); if(!t)return res.status(401).json({error:'Login required'});
  try{req.user=jwt.verify(t,process.env.JWT_SECRET);next()}catch{return res.status(401).json({error:'Invalid or expired session'})}
}
function requireAdmin(req,res,next){if(req.user?.role!=='admin')return res.status(403).json({error:'Admin access required'});next()}
function actor(req){const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();const ua=String(req.headers['user-agent']||'').slice(0,200);return crypto.createHash('sha256').update(ip+'|'+ua).digest('hex')}

async function setting(k,fallback=null){const r=await sql`SELECT value FROM settings WHERE key=${k} LIMIT 1`;return r[0]?.value??fallback}
async function setSetting(k,v){await sql`INSERT INTO settings(key,value) VALUES(${k},${JSON.stringify(v)}::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`}
async function commentsFor(id){const r=await sql`SELECT id,author,text,reply,created_at AS time FROM comments WHERE post_id=${id} ORDER BY id ASC`;return r.map(c=>({...c,id:Number(c.id)}))}
async function posts(includeDrafts=false){const r=includeDrafts?await sql`SELECT id,title,text,date_text AS date,status,pinned,likes FROM posts ORDER BY pinned DESC,id DESC`:await sql`SELECT id,title,text,date_text AS date,status,pinned,likes FROM posts WHERE status='publish' ORDER BY pinned DESC,id DESC`;return Promise.all(r.map(async p=>({...p,id:Number(p.id),pinned:Boolean(p.pinned),likes:Number(p.likes),comments:await commentsFor(p.id)})))}
async function snapshot(includeDrafts=false){const sections={};for(const k of SECTIONS)sections[k]=await setting(`section:${k}`,null);const likes={};const lr=await sql`SELECT section_key,COUNT(*)::int AS count FROM section_likes GROUP BY section_key`;for(const k of SECTIONS)likes[k]=0;for(const r of lr)likes[r.section_key]=Number(r.count);return {posts:await posts(includeDrafts),socialLinks:await setting('socialLinks',{}),sections,sectionLikes:likes}}

app.get('/api/health',async(req,res)=>res.json({ok:true,database:'postgres',service:'rajnikalam',time:new Date().toISOString()}));
app.post('/api/auth/register',authLimit,async(req,res)=>{const n=text(req.body.name,80)||'Reader',e=email(req.body.email),p=String(req.body.password||'');if(!/^\S+@\S+\.\S+$/.test(e))return res.status(400).json({error:'Valid email required'});if(p.length<8)return res.status(400).json({error:'Password must be at least 8 characters'});try{const h=await bcrypt.hash(p,12);const r=await sql`INSERT INTO users(name,email,password_hash,role) VALUES(${n},${e},${h},'user') RETURNING id,name,email,role`;res.status(201).json({user:userView(r[0]),token:tokenFor(r[0])})}catch(err){if(String(err.message).includes('duplicate'))return res.status(409).json({error:'Account already exists'});console.error(err);res.status(500).json({error:'Registration failed'})}});
app.post('/api/auth/login',authLimit,async(req,res)=>{const e=email(req.body.email),p=String(req.body.password||'');const r=await sql`SELECT * FROM users WHERE email=${e} LIMIT 1`;if(!r[0]||!(await bcrypt.compare(p,r[0].password_hash)))return res.status(401).json({error:'Invalid email or password'});res.json({user:userView(r[0]),token:tokenFor(r[0])})});
app.get('/api/auth/me',requireAuth,(req,res)=>res.json({user:req.user}));
app.get('/api/site',async(req,res)=>res.json(await snapshot(false)));
app.get('/api/admin/site',requireAuth,requireAdmin,async(req,res)=>res.json(await snapshot(true)));

app.post('/api/posts',requireAuth,requireAdmin,async(req,res)=>{const t=text(req.body.title,240)||'સાહિત્યિક પોસ્ટ',x=text(req.body.text,30000),s=req.body.status==='draft'?'draft':'publish';if(!x)return res.status(400).json({error:'Post text required'});const r=await sql`INSERT INTO posts(title,text,date_text,status) VALUES(${t},${x},${today()},${s}) RETURNING id,title,text,date_text AS date,status,pinned,likes`;await autoPublish(`Create post: ${t}`);res.status(201).json({post:r[0]})});
app.patch('/api/posts/:id',requireAuth,requireAdmin,async(req,res)=>{const id=Number(req.params.id),old=(await sql`SELECT * FROM posts WHERE id=${id} LIMIT 1`)[0];if(!old)return res.status(404).json({error:'Post not found'});const t=text(req.body.title??old.title,240)||old.title,x=text(req.body.text??old.text,30000),s=req.body.status==='draft'||req.body.status==='publish'?req.body.status:old.status,p=req.body.pinned===undefined?old.pinned:Boolean(req.body.pinned);const r=await sql`UPDATE posts SET title=${t},text=${x},status=${s},pinned=${p},updated_at=NOW() WHERE id=${id} RETURNING id,title,text,date_text AS date,status,pinned,likes`;await autoPublish(`Update post: ${t}`);res.json({post:r[0]})});
app.delete('/api/posts/:id',requireAuth,requireAdmin,async(req,res)=>{const id=Number(req.params.id),r=await sql`DELETE FROM posts WHERE id=${id}`;if(!r.count)return res.status(404).json({error:'Post not found'});await autoPublish(`Delete post: ${id}`);res.json({ok:true})});
app.post('/api/posts/:id/like',async(req,res)=>{const id=Number(req.params.id),p=(await sql`SELECT id,likes FROM posts WHERE id=${id} AND status='publish' LIMIT 1`)[0];if(!p)return res.status(404).json({error:'Post not found'});const ins=await sql`INSERT INTO likes(post_id,actor_key) VALUES(${id},${actor(req)}) ON CONFLICT(post_id,actor_key) DO NOTHING RETURNING id`;if(ins.length)await sql`UPDATE posts SET likes=likes+1 WHERE id=${id}`;const c=(await sql`SELECT likes FROM posts WHERE id=${id}`)[0];res.json({liked:Boolean(ins.length),likes:Number(c.likes)})});
app.get('/api/posts/:id/comments',async(req,res)=>res.json({comments:await commentsFor(Number(req.params.id))}));
app.post('/api/posts/:id/comments',async(req,res)=>{const id=Number(req.params.id);if(!(await sql`SELECT id FROM posts WHERE id=${id} AND status='publish' LIMIT 1`)[0])return res.status(404).json({error:'Post not found'});const a=text(req.body.author,80)||'અનામિક યુઝર',x=text(req.body.text,2000);if(!x)return res.status(400).json({error:'Comment text required'});const r=await sql`INSERT INTO comments(post_id,author,text) VALUES(${id},${a},${x}) RETURNING id,author,text,reply,created_at AS time`;res.status(201).json({comment:{...r[0],id:Number(r[0].id)}})});
app.patch('/api/comments/:id/reply',requireAuth,requireAdmin,async(req,res)=>{const r=await sql`UPDATE comments SET reply=${text(req.body.reply,2000)||null} WHERE id=${Number(req.params.id)}`;if(!r.count)return res.status(404).json({error:'Comment not found'});res.json({ok:true})});
app.delete('/api/comments/:id',requireAuth,requireAdmin,async(req,res)=>{const r=await sql`DELETE FROM comments WHERE id=${Number(req.params.id)}`;if(!r.count)return res.status(404).json({error:'Comment not found'});res.json({ok:true})});
app.post('/api/sections/:key/like',async(req,res)=>{const k=String(req.params.key);if(!SECTIONS.includes(k))return res.status(404).json({error:'Section not found'});const r=await sql`INSERT INTO section_likes(section_key,actor_key) VALUES(${k},${actor(req)}) ON CONFLICT(section_key,actor_key) DO NOTHING RETURNING id`;const c=(await sql`SELECT COUNT(*)::int AS count FROM section_likes WHERE section_key=${k}`)[0];res.json({liked:Boolean(r.length),likes:Number(c.count)})});
app.get('/api/sections/:key',async(req,res)=>{const k=String(req.params.key);if(!SECTIONS.includes(k))return res.status(404).json({error:'Section not found'});res.json({key:k,section:await setting(`section:${k}`,null)})});
app.put('/api/admin/sections/:key',requireAuth,requireAdmin,async(req,res)=>{const k=String(req.params.key);if(!SECTIONS.includes(k))return res.status(404).json({error:'Section not found'});const s={title:text(req.body.title,240),content:text(req.body.content,30000),extraBoxes:Array.isArray(req.body.extraBoxes)?req.body.extraBoxes.slice(0,50).map(b=>({title:text(b?.title,240),content:text(b?.content,30000),status:b?.status==='draft'?'draft':'publish'})):[]};await setSetting(`section:${k}`,s);await autoPublish(`Update section: ${k}`);res.json({key:k,section:s})});
app.put('/api/settings/social',requireAuth,requireAdmin,async(req,res)=>{const out={};for(const k of ['instagram','facebook','youtube','twitter','whatsapp']){const v=text(req.body[k],500);if(!v){out[k]='';continue}try{const u=new URL(v);if(!['http:','https:'].includes(u.protocol))throw 0;out[k]=u.href}catch{return res.status(400).json({error:`Invalid URL for ${k}`})}}await setSetting('socialLinks',out);await autoPublish('Update social links');res.json({socialLinks:out})});

async function github(snapshot,msg){const {GITHUB_TOKEN:t,GITHUB_OWNER:o,GITHUB_REPO:r,GITHUB_BRANCH:b='main',GITHUB_PATH:f='data.json'}=process.env;if(!t||!o||!r)return{skipped:true};const u=`https://api.github.com/repos/${encodeURIComponent(o)}/${encodeURIComponent(r)}/contents/${f.split('/').map(encodeURIComponent).join('/')}`,h={Authorization:`Bearer ${t}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'};const g=await fetch(`${u}?ref=${encodeURIComponent(b)}`,{headers:h});let sha=null;if(g.ok)sha=(await g.json()).sha||null;else if(g.status!==404)throw Error(`GitHub read failed: ${g.status}`);const body={message:msg||'RajNiKalam update',content:Buffer.from(JSON.stringify(snapshot,null,2)).toString('base64'),branch:b};if(sha)body.sha=sha;const p=await fetch(u,{method:'PUT',headers:h,body:JSON.stringify(body)});if(!p.ok)throw Error(`GitHub write failed: ${p.status}`);return{ok:true,skipped:false}}
async function autoPublish(msg){if(String(process.env.GITHUB_AUTO_PUBLISH||'').toLowerCase()!=='true')return{skipped:true};try{return await github(await snapshot(true),msg)}catch(e){console.warn(e.message);return{ok:false,error:e.message}}}
app.post('/api/admin/publish-github',requireAuth,requireAdmin,async(req,res)=>{try{res.json(await github(await snapshot(true),text(req.body.message,200)||'RajNiKalam admin publish'))}catch(e){res.status(502).json({error:e.message})}});

// Compatibility endpoint used by the existing frontend: sync its current state into Postgres.
app.put('/api/admin/snapshot',requireAuth,requireAdmin,async(req,res)=>{const d=req.body||{},ps=Array.isArray(d.posts)?d.posts.slice(0,500):[];await sql`DELETE FROM comments`;await sql`DELETE FROM likes`;await sql`DELETE FROM posts`;for(const p of ps){const r=await sql`INSERT INTO posts(title,text,date_text,status,pinned,likes) VALUES(${text(p.title,240)||'સાહિત્યિક પોસ્ટ'},${text(p.text,30000)},${text(p.date,80)||today()},${p.status==='draft'?'draft':'publish'},${Boolean(p.pinned)},${Math.max(0,Number(p.likes)||0)}) RETURNING id`;for(const c of (Array.isArray(p.comments)?p.comments:[]).slice(0,100))await sql`INSERT INTO comments(post_id,author,text,reply) VALUES(${r[0].id},${text(c.author,80)||'અનામિક યુઝર'},${text(c.text,2000)},${text(c.reply,2000)||null})`}if(d.socialLinks)await setSetting('socialLinks',d.socialLinks);if(d.sections)for(const k of SECTIONS)if(d.sections[k])await setSetting(`section:${k}`,d.sections[k]);await autoPublish('RajNiKalam snapshot update');res.json({ok:true,site:await snapshot(true)})});
app.get('/api/admin/stats',requireAuth,requireAdmin,async(req,res)=>{const r=await sql`SELECT (SELECT COUNT(*) FROM users)::int AS users,(SELECT COUNT(*) FROM posts)::int AS posts,(SELECT COUNT(*) FROM posts WHERE status='publish')::int AS "publishedPosts",(SELECT COUNT(*) FROM posts WHERE status='draft')::int AS drafts,(SELECT COUNT(*) FROM comments)::int AS comments,(SELECT COUNT(*) FROM likes)::int AS likes`;res.json(r[0])});
app.get('/api/admin/comments',requireAuth,requireAdmin,async(req,res)=>{const r=await sql`SELECT c.id,c.author,c.text,c.reply,c.created_at AS time,p.id AS post_id,p.title AS post_title FROM comments c JOIN posts p ON p.id=c.post_id ORDER BY c.id DESC`;res.json({comments:r.map(c=>({...c,id:Number(c.id),post_id:Number(c.post_id)}))})});

app.use(express.static(path.join(__dirname,'public'),{maxAge:process.env.NODE_ENV==='production'?'1h':0}));
app.use((req,res,next)=>{if(req.method==='GET'&&!req.path.startsWith('/api/'))return res.sendFile(path.join(__dirname,'public','index.html'));next()});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Internal server error'})});
if(!VERCEL)app.listen(PORT,()=>console.log(`RajNiKalam running on http://localhost:${PORT}`));
module.exports=app;
