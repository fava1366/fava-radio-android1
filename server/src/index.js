import 'dotenv/config';
import express from 'express';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { Server as SocketServer } from 'socket.io';
import { AccessToken } from '@livekit/server-sdk';

const { Pool } = pg;
const app = express();
const server = http.createServer(app);
const port = Number(process.env.PORT || 10000);
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 32) {
  console.error('FATAL: set JWT_SECRET to a random value at least 32 characters long.');
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
const io = new SocketServer(server, { cors: { origin: process.env.CORS_ORIGIN?.split(',') || '*', methods: ['GET','POST'] } });
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
const corsOrigin = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(v=>v.trim()) : '*';
app.use(cors({ origin: corsOrigin, credentials: true }));
app.use(express.json({ limit: '2mb' }));

const schema = `
CREATE TABLE IF NOT EXISTS users (
 id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', active BOOLEAN NOT NULL DEFAULT TRUE,
 permissions JSONB NOT NULL DEFAULT '{"ptt":true,"audio":true,"video":false,"chat":true,"media":true,"location":false}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS channels (
 id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT NOT NULL DEFAULT '',
 private BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS channel_members (
 channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(channel_id,user_id)
);
CREATE TABLE IF NOT EXISTS messages (
 id BIGSERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 recipient_id INTEGER REFERENCES users(id) ON DELETE SET NULL, channel_id INTEGER REFERENCES channels(id) ON DELETE SET NULL,
 kind TEXT NOT NULL DEFAULT 'text', body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS messages_channel_created_idx ON messages(channel_id,created_at DESC);
`;

async function init() {
  await pool.query(schema);
  await pool.query("INSERT INTO channels(name,description,private) VALUES('کانال اصلی','کانال عمومی ارتباطی',false) ON CONFLICT(name) DO NOTHING");
  const username = process.env.ADMIN_BOOTSTRAP_USERNAME || 'admin';
  const password = process.env.ADMIN_BOOTSTRAP_PASSWORD;
  if (password && password.length >= 12) {
    const exists = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
    if (!exists.rowCount) {
      const hash = await bcrypt.hash(password, 12);
      const result = await pool.query("INSERT INTO users(username,display_name,password_hash,role,permissions) VALUES($1,$2,$3,'admin',$4) RETURNING id", [username, 'مدیر فاوا رادیو', hash, JSON.stringify({ptt:true,audio:true,video:true,chat:true,media:true,location:true,manageUsers:true,manageChannels:true})]);
      console.log(`Bootstrap admin created: ${username} (password is not logged)`);
    }
  } else {
    console.warn('ADMIN_BOOTSTRAP_PASSWORD is missing or shorter than 12 chars; bootstrap admin was not created.');
  }
}

function auth(req,res,next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try { req.user = jwt.verify(token, jwtSecret); next(); }
  catch { return res.status(401).json({error:'لطفاً دوباره وارد شوید.'}); }
}
function admin(req,res,next) { if (req.user?.role !== 'admin') return res.status(403).json({error:'دسترسی مدیر لازم است.'}); next(); }
function can(req, permission) { return req.user?.role === 'admin' || req.user?.permissions?.[permission] === true; }
function safeUser(row) { return {id:row.id,username:row.username,displayName:row.display_name,role:row.role,active:row.active,permissions:row.permissions,createdAt:row.created_at}; }

app.get('/health', (_req,res) => res.json({ok:true,service:'fava-radio-api',time:new Date().toISOString()}));
app.post('/api/auth/login', async (req,res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const q = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    const user = q.rows[0];
    if (!user || !user.active || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:'شناسه یا رمز عبور نادرست است.'});
    const token = jwt.sign({id:user.id,username:user.username,role:user.role,permissions:user.permissions},jwtSecret,{expiresIn:'12h'});
    res.json({token,user:safeUser(user)});
  } catch(e) { console.error(e); res.status(500).json({error:'خطای سرور'}); }
});
app.post('/api/auth/register', async (req,res) => {
  try {
    const {username,displayName,password,inviteCode} = req.body || {};
    if (!process.env.INVITE_CODE || inviteCode !== process.env.INVITE_CODE) return res.status(403).json({error:'کد دعوت معتبر نیست.'});
    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(String(username||''))) return res.status(400).json({error:'شناسه باید ۳ تا ۳۲ حرف انگلیسی یا عدد باشد.'});
    if (String(password||'').length < 10) return res.status(400).json({error:'رمز عبور باید حداقل ۱۰ کاراکتر باشد.'});
    const hash = await bcrypt.hash(password,12);
    const result = await pool.query('INSERT INTO users(username,display_name,password_hash) VALUES($1,$2,$3) RETURNING *',[username.toLowerCase(),String(displayName||username).slice(0,80),hash]);
    const user = result.rows[0];
    const token = jwt.sign({id:user.id,username:user.username,role:user.role,permissions:user.permissions},jwtSecret,{expiresIn:'12h'});
    res.status(201).json({token,user:safeUser(user)});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'این شناسه قبلاً ثبت شده است.'}); console.error(e); res.status(500).json({error:'خطای سرور'}); }
});
app.get('/api/me',auth,async(req,res)=>{const q=await pool.query('SELECT * FROM users WHERE id=$1',[req.user.id]);if(!q.rowCount||!q.rows[0].active)return res.status(401).json({error:'حساب غیرفعال است'});res.json({user:safeUser(q.rows[0])});});
app.get('/api/channels',auth,async(req,res)=>{const q=await pool.query(`SELECT c.*, COUNT(cm.user_id)::int AS member_count FROM channels c LEFT JOIN channel_members cm ON cm.channel_id=c.id WHERE c.private=false OR EXISTS(SELECT 1 FROM channel_members x WHERE x.channel_id=c.id AND x.user_id=$1) OR $2='admin' GROUP BY c.id ORDER BY c.id`,[req.user.id,req.user.role]);res.json({channels:q.rows});});
app.post('/api/channels',auth,admin,async(req,res)=>{try{const name=String(req.body.name||'').trim().slice(0,80);if(!name)return res.status(400).json({error:'نام کانال لازم است'});const q=await pool.query('INSERT INTO channels(name,description,private) VALUES($1,$2,$3) RETURNING *',[name,String(req.body.description||'').slice(0,250),Boolean(req.body.private)]);io.emit('channels:changed');res.status(201).json({channel:q.rows[0]});}catch(e){if(e.code==='23505')return res.status(409).json({error:'نام کانال تکراری است'});res.status(500).json({error:'خطای سرور'});}});
app.patch('/api/channels/:id',auth,admin,async(req,res)=>{const id=Number(req.params.id);const q=await pool.query('UPDATE channels SET name=COALESCE($2,name),description=COALESCE($3,description),private=COALESCE($4,private) WHERE id=$1 RETURNING *',[id,req.body.name?String(req.body.name).slice(0,80):null,req.body.description!==undefined?String(req.body.description).slice(0,250):null,typeof req.body.private==='boolean'?req.body.private:null]);if(!q.rowCount)return res.status(404).json({error:'کانال پیدا نشد'});io.emit('channels:changed');res.json({channel:q.rows[0]});});
app.delete('/api/channels/:id',auth,admin,async(req,res)=>{await pool.query('DELETE FROM channels WHERE id=$1',[Number(req.params.id)]);io.emit('channels:changed');res.json({ok:true});});
app.get('/api/admin/users',auth,admin,async(_req,res)=>{const q=await pool.query('SELECT * FROM users ORDER BY id');res.json({users:q.rows.map(safeUser)});});
app.post('/api/admin/users',auth,admin,async(req,res)=>{try{const username=String(req.body.username||'').trim().toLowerCase();const displayName=String(req.body.displayName||username).slice(0,80);const password=String(req.body.password||'');if(!/^[a-zA-Z0-9_.-]{3,32}$/.test(username))return res.status(400).json({error:'شناسه نامعتبر است'});if(password.length<10)return res.status(400).json({error:'رمز عبور باید حداقل ۱۰ کاراکتر باشد'});const hash=await bcrypt.hash(password,12);const permissions={ptt:true,audio:true,video:false,chat:true,media:true,location:false};const q=await pool.query('INSERT INTO users(username,display_name,password_hash,role,permissions) VALUES($1,$2,$3,$4,$5) RETURNING *',[username,displayName,hash,req.body.role==='admin'?'admin':'user',JSON.stringify(permissions)]);res.status(201).json({user:safeUser(q.rows[0])});}catch(e){if(e.code==='23505')return res.status(409).json({error:'شناسه تکراری است'});console.error(e);res.status(500).json({error:'خطای سرور'});}});
app.patch('/api/admin/users/:id',auth,admin,async(req,res)=>{const id=Number(req.params.id);if(id===req.user.id&&req.body.active===false)return res.status(400).json({error:'مدیر نمی‌تواند حساب خودش را غیرفعال کند'});const fields=[];const values=[id];if(typeof req.body.active==='boolean'){values.push(req.body.active);fields.push(`active=$${values.length}`)}if(['user','admin'].includes(req.body.role)){values.push(req.body.role);fields.push(`role=$${values.length}`)}if(req.body.permissions&&typeof req.body.permissions==='object'){const allowed=['ptt','audio','video','chat','media','location','manageUsers','manageChannels'];const p={};for(const k of allowed)p[k]=req.body.permissions[k]===true;values.push(JSON.stringify(p));fields.push(`permissions=$${values.length}::jsonb`)}if(!fields.length)return res.status(400).json({error:'تغییری ارسال نشده است'});const q=await pool.query(`UPDATE users SET ${fields.join(',')} WHERE id=$1 RETURNING *`,values);if(!q.rowCount)return res.status(404).json({error:'کاربر پیدا نشد'});res.json({user:safeUser(q.rows[0])});});
app.post('/api/livekit/token',auth,async(req,res)=>{try{if(!process.env.LIVEKIT_URL||!process.env.LIVEKIT_API_KEY||!process.env.LIVEKIT_API_SECRET)return res.status(503).json({error:'سرویس تماس هنوز پیکربندی نشده است.'});const room=String(req.body.room||'main').replace(/[^a-zA-Z0-9_-]/g,'').slice(0,64);const mode=req.body.mode==='video'?'video':'audio';if(mode==='video'&&!can(req,'video'))return res.status(403).json({error:'مجوز تماس تصویری ندارید.'});if(mode==='audio'&&!can(req,'audio'))return res.status(403).json({error:'مجوز تماس صوتی ندارید.'});const at=new AccessToken(process.env.LIVEKIT_API_KEY,process.env.LIVEKIT_API_SECRET,{identity:String(req.user.id),name:String(req.user.username),ttl:'1h'});at.addGrant({roomJoin:true,room,canPublish: true,canSubscribe:true,canPublishData:true});res.json({serverUrl:process.env.LIVEKIT_URL,token:await at.toJwt(),room,mode});}catch(e){console.error(e);res.status(500).json({error:'ساخت توکن تماس ناموفق بود'});}});
app.get('/api/messages',auth,async(req,res)=>{if(!can(req,'chat'))return res.status(403).json({error:'مجوز پیام‌رسانی ندارید'});const channelId=req.query.channelId?Number(req.query.channelId):null;const otherId=req.query.userId?Number(req.query.userId):null;let q;if(channelId){q=await pool.query(`SELECT m.id,m.sender_id,m.recipient_id,m.channel_id,m.kind,m.body,m.created_at,u.username AS sender_name FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.channel_id=$1 ORDER BY m.created_at DESC LIMIT 100`,[channelId]);}else if(otherId){q=await pool.query(`SELECT m.id,m.sender_id,m.recipient_id,m.channel_id,m.kind,m.body,m.created_at,u.username AS sender_name FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE (m.sender_id=$1 AND m.recipient_id=$2) OR (m.sender_id=$2 AND m.recipient_id=$1) ORDER BY m.created_at DESC LIMIT 100`,[req.user.id,otherId]);}else return res.status(400).json({error:'channelId یا userId لازم است'});res.json({messages:q.rows.reverse()});});

const socketAuth = async (socket,next)=>{try{const token=socket.handshake.auth?.token;if(!token)throw new Error('no token');const decoded=jwt.verify(token,jwtSecret);const q=await pool.query('SELECT id,username,role,active,permissions FROM users WHERE id=$1',[decoded.id]);if(!q.rowCount||!q.rows[0].active)throw new Error('inactive');socket.user={...q.rows[0],permissions:q.rows[0].permissions};next();}catch{next(new Error('احراز هویت ناموفق'));}};
io.use(socketAuth);
io.on('connection',(socket)=>{
 socket.on('channel:join',async({channelId}={},ack=()=>{})=>{try{const q=await pool.query('SELECT * FROM channels WHERE id=$1',[Number(channelId)]);if(!q.rowCount)return ack({error:'کانال پیدا نشد'});const c=q.rows[0];if(c.private&&socket.user.role!=='admin'){const m=await pool.query('SELECT 1 FROM channel_members WHERE channel_id=$1 AND user_id=$2',[c.id,socket.user.id]);if(!m.rowCount)return ack({error:'دسترسی به کانال ندارید'});}socket.join(`channel:${c.id}`);ack({ok:true});}catch{ack({error:'خطای سرور'});}});
 socket.on('message:send',async(data={},ack=()=>{})=>{try{if(!(socket.user.role==='admin'||socket.user.permissions?.chat))return ack({error:'مجوز پیام ندارید'});const body=String(data.body||'').trim();if(!body||body.length>2000)return ack({error:'متن پیام نامعتبر است'});const kind=['text','image','video'].includes(data.kind)?data.kind:'text';const channelId=data.channelId?Number(data.channelId):null;const recipientId=data.recipientId?Number(data.recipientId):null;if(!channelId&&!recipientId)return ack({error:'مقصد پیام مشخص نیست'});if(kind!=='text'&&!(socket.user.role==='admin'||socket.user.permissions?.media))return ack({error:'مجوز ارسال فایل ندارید'});const q=await pool.query('INSERT INTO messages(sender_id,recipient_id,channel_id,kind,body) VALUES($1,$2,$3,$4,$5) RETURNING *',[socket.user.id,recipientId,channelId,kind,body]);const msg={...q.rows[0],sender_name:socket.user.username};if(channelId)io.to(`channel:${channelId}`).emit('message:new',msg);else io.to(`user:${recipientId}`).emit('message:new',msg),socket.emit('message:new',msg);ack({ok:true,message:msg});}catch(e){console.error(e);ack({error:'ارسال پیام انجام نشد'});}});
 socket.join(`user:${socket.user.id}`);socket.emit('session:ready',{id:socket.user.id,username:socket.user.username});
});

const here = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(here, '../../web/dist');
app.use(express.static(webDist));
app.get('*', (req,res,next) => { if(req.path.startsWith('/api/') || req.path.startsWith('/socket.io')) return next(); res.sendFile(path.join(webDist,'index.html'), err => { if(err) next(); }); });

await init();
server.listen(port,'0.0.0.0',()=>console.log(`Fava Radio API listening on ${port}`));
