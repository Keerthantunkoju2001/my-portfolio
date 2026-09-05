const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');
const serverless = require('serverless-http');

const app = express();
app.use(helmet({ contentSecurityPolicy:false, crossOriginResourcePolicy:{policy:'cross-origin'} }));
app.use(cors());
app.use(express.json({ limit:'2mb' }));

const dataStore = getStore('portfolio-data');
const uploadStore = getStore('portfolio-uploads');

const loginLimiter = rateLimit({ windowMs:15*60*1000, max:20, standardHeaders:true, legacyHeaders:false });
const contactLimiter = rateLimit({ windowMs:60*60*1000, max:10, standardHeaders:true, legacyHeaders:false });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req,file,cb) => cb(null, [
    'image/jpeg','image/png','image/webp','image/gif','application/pdf'
  ].includes(file.mimetype))
});

const DEFAULT_PORTFOLIO = { profile:{}, about:{}, skills:[], projects:[], experience:[], education:[], certifications:[], achievements:[], resumeFile:{filename:'',url:'',updatedAt:''}, seo:{}, visibility:{}, order:[], theme:'light' };

async function readData(key, fallback) {
  const value = await dataStore.get(key, { type:'json' });
  return value == null ? fallback : value;
}
async function writeData(key, value) { await dataStore.setJSON(key, value); }
function isValidEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v||'')); }
function escapeHtml(v) { return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;'); }
function signToken() {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not configured in Netlify.');
  return jwt.sign({role:'admin'}, process.env.JWT_SECRET, {expiresIn:'7d'});
}
function requireAuth(req,res,next) {
  const header=req.headers.authorization||'';
  const token=header.startsWith('Bearer ') ? header.slice(7) : null;
  if(!token) return res.status(401).json({error:'Missing authorization token.'});
  try { req.admin=jwt.verify(token,process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'Invalid or expired session. Please log in again.'}); }
}

// AUTH
app.get('/auth/status', async (req,res)=>res.json({passwordSet:!!(await readData('auth',{passwordHash:null})).passwordHash}));
app.post('/auth/setup',loginLimiter,async(req,res)=>{
  const auth=await readData('auth',{passwordHash:null});
  if(auth.passwordHash) return res.status(409).json({error:'A password is already set. Use login instead.'});
  const {password}=req.body||{};
  if(!password||String(password).length<6) return res.status(400).json({error:'Password must be at least 6 characters.'});
  await writeData('auth',{passwordHash:await bcrypt.hash(String(password),12)});
  res.json({token:signToken()});
});
app.post('/auth/login',loginLimiter,async(req,res)=>{
  const auth=await readData('auth',{passwordHash:null});
  if(!auth.passwordHash) return res.status(409).json({error:'No password set yet. Please complete setup first.'});
  const {password}=req.body||{};
  if(!password||!(await bcrypt.compare(String(password),auth.passwordHash))) return res.status(401).json({error:'Incorrect password.'});
  res.json({token:signToken()});
});
app.post('/auth/change-password',requireAuth,async(req,res)=>{
  const auth=await readData('auth',{passwordHash:null});
  const {oldPassword,newPassword}=req.body||{};
  if(!oldPassword||!auth.passwordHash||!(await bcrypt.compare(String(oldPassword),auth.passwordHash))) return res.status(401).json({error:'Current password is incorrect.'});
  if(!newPassword||String(newPassword).length<6) return res.status(400).json({error:'New password must be at least 6 characters.'});
  await writeData('auth',{passwordHash:await bcrypt.hash(String(newPassword),12)});
  res.json({ok:true});
});

// PORTFOLIO
app.get('/portfolio',async(req,res)=>res.json(await readData('portfolio',DEFAULT_PORTFOLIO)));
app.put('/portfolio',requireAuth,async(req,res)=>{
  if(!req.body||typeof req.body!=='object'||Array.isArray(req.body)) return res.status(400).json({error:'Request body must be a portfolio object.'});
  await writeData('portfolio',req.body);
  res.json({ok:true,savedAt:new Date().toISOString()});
});

// CONTACT + EMAIL
app.post('/contact',contactLimiter,async(req,res)=>{
  const {name,email,message}=req.body||{};
  if(!name||!String(name).trim()) return res.status(400).json({error:'Name is required.'});
  if(!isValidEmail(email)) return res.status(400).json({error:'A valid email is required.'});
  if(!message||!String(message).trim()) return res.status(400).json({error:'Message is required.'});

  const entry={id:crypto.randomUUID(),name:String(name).trim().slice(0,200),email:String(email).trim().slice(0,200),message:String(message).trim().slice(0,5000),receivedAt:new Date().toISOString(),read:false};
  const contacts=await readData('contacts',[]);
  contacts.unshift(entry);
  await writeData('contacts',contacts);

  if(!(process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS&&process.env.CONTACT_TO_EMAIL))
    return res.status(503).json({error:'Message was saved, but email notifications are not configured.',saved:true,emailSent:false});

  try {
    const port=Number(process.env.SMTP_PORT||465);
    const transporter=nodemailer.createTransport({host:process.env.SMTP_HOST,port,secure:port===465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
    await transporter.sendMail({
      from:`"Portfolio Contact Form" <${process.env.SMTP_USER}>`,to:process.env.CONTACT_TO_EMAIL,replyTo:entry.email,
      subject:`New portfolio message from ${entry.name}`,
      text:`You received a new message from your portfolio.\n\nName: ${entry.name}\nEmail: ${entry.email}\n\nMessage:\n${entry.message}`,
      html:`<div style="font-family:Arial;line-height:1.6"><h2>New Portfolio Contact Message</h2><p><b>Name:</b> ${escapeHtml(entry.name)}</p><p><b>Email:</b> ${escapeHtml(entry.email)}</p><p><b>Message:</b></p><div style="padding:15px;background:#f5f5f5;border-radius:8px;white-space:pre-wrap">${escapeHtml(entry.message)}</div></div>`
    });
    console.log('EMAIL SENT:',process.env.CONTACT_TO_EMAIL);
    res.json({ok:true,saved:true,emailSent:true});
  } catch(e) {
    console.error('EMAIL FAILED:',e.message);
    res.status(502).json({error:'Message was saved, but the email notification could not be sent.',saved:true,emailSent:false});
  }
});
app.get('/contact',requireAuth,async(req,res)=>res.json(await readData('contacts',[])));
app.patch('/contact/:id/read',requireAuth,async(req,res)=>{
  const contacts=await readData('contacts',[]), entry=contacts.find(c=>c.id===req.params.id);
  if(!entry) return res.status(404).json({error:'Message not found.'});
  entry.read=true; await writeData('contacts',contacts); res.json({ok:true});
});
app.delete('/contact/:id',requireAuth,async(req,res)=>{
  const contacts=await readData('contacts',[]); await writeData('contacts',contacts.filter(c=>c.id!==req.params.id)); res.json({ok:true});
});

// UPLOADS - persisted in Netlify Blobs
app.post('/upload',requireAuth,(req,res)=>{
  upload.single('file')(req,res,async(err)=>{
    if(err) return res.status(400).json({error:err.message});
    if(!req.file) return res.status(400).json({error:'No file received.'});
    const key=`${Date.now()}-${crypto.randomBytes(6).toString('hex')}-${req.file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_')}`;
    await uploadStore.set(key,req.file.buffer,{metadata:{contentType:req.file.mimetype,originalName:req.file.originalname}});
    res.json({url:`/uploads/${encodeURIComponent(key)}`,filename:req.file.originalname});
  });
});
app.get('/uploads/:key',async(req,res)=>{
  const result=await uploadStore.getWithMetadata(decodeURIComponent(req.params.key),{type:'arrayBuffer'});
  if(!result) return res.status(404).send('File not found.');
  res.setHeader('Content-Type',result.metadata?.contentType||'application/octet-stream');
  res.setHeader('Cache-Control','public,max-age=31536000,immutable');
  res.send(Buffer.from(result.data));
});

app.get('/health',(req,res)=>res.json({ok:true,time:new Date().toISOString()}));
app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:'Something went wrong on the server.'}); });

module.exports.handler=serverless(app);
