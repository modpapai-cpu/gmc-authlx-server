import express from "express";
import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const app = express();
app.use(express.json({ limit: "20kb" }));
app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type");
  if(req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const AUTHLX_URL=(process.env.AUTHLX_URL||"https://api.authlx.com/api/v2/client/").replace(/\/$/,"");
const NAME=process.env.AUTHLX_NAME||"SteamTool";
const OWNERID=process.env.AUTHLX_OWNERID||"";
const VERSION=process.env.AUTHLX_VERSION||"1.0";
const SECRET=process.env.AUTHLX_SECRET||"";
const DATABASE_URL=process.env.DATABASE_URL||"";

if(!DATABASE_URL){
  console.error("DATABASE_URL is required for persistent 1-license/1-installation binding.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized:false } : undefined
});

function nonce(){ return crypto.randomBytes(16).toString("hex"); }
function hmac(key,msg){ return crypto.createHmac("sha256",key).update(msg,"utf8").digest("hex"); }
function canonical(v){
  if(v===null) return "null";
  if(Array.isArray(v)) return "["+v.map(canonical).join(",")+"]";
  if(typeof v==="object") return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}";
  if(typeof v==="string") return JSON.stringify(v);
  if(typeof v==="boolean"||typeof v==="number") return String(v);
  return JSON.stringify(String(v));
}
function licenseHash(license){
  return crypto.createHash("sha256").update(String(license).trim(),"utf8").digest("hex");
}

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gmc_license_bindings (
      license_hash TEXT PRIMARY KEY,
      installation_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function authlx(endpoint,payload){
  const requestNonce=nonce();
  const r=await fetch(`${AUTHLX_URL}/${endpoint}`,{
    method:"POST",
    headers:{
      "Content-Type":"application/json; charset=UTF-8",
      "Accept":"application/json",
      "User-Agent":`AuthLX-SDK-Java/1.0 (${NAME})`,
      "X-Request-Nonce":requestNonce
    },
    body:JSON.stringify(payload)
  });
  const text=await r.text();
  let data=null; try{data=JSON.parse(text);}catch{}
  if(SECRET){
    const sig=r.headers.get("x-response-sig");
    const nonceHeader=r.headers.get("x-response-nonce");
    if(sig && nonceHeader){
      if(nonceHeader.toLowerCase()!==requestNonce.toLowerCase()) throw new Error("AuthLX response nonce mismatch");
      const expected=hmac(SECRET,canonical(data??text)+":"+requestNonce);
      const a=Buffer.from(expected.toLowerCase()),b=Buffer.from(sig.toLowerCase());
      if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) throw new Error("AuthLX response signature mismatch");
    }
  }
  if(!r.ok){
    const e=new Error(`AuthLX HTTP ${r.status}: ${data?.message||text||"request failed"}`);
    e.status=r.status; e.data=data; throw e;
  }
  if(!data) throw new Error("Invalid AuthLX JSON response");
  return data;
}

function base(hwid){ return {app_id:OWNERID,name:NAME,version:VERSION,hwid:hwid||""}; }
function tokenOf(x){ return x?.session_token||x?.data?.token||x?.token||""; }

async function initialize(){
  const r=await authlx("init",{app_id:OWNERID,name:NAME,version:VERSION});
  if(String(r?.status||"").toLowerCase()!=="success") throw new Error(r?.message||"AuthLX initialization failed");
  return r;
}

async function authenticate(license,hwid){
  const init=await initialize();
  const initToken=tokenOf(init);
  const loginPayload={...base(hwid),username:license,password:license,...(initToken?{session_token:initToken}:{})};
  try{
    const login=await authlx("login",loginPayload);
    if(String(login?.status||"").toLowerCase()==="success"){
      return {valid:true,stage:"login",message:login.message||"License valid",session_token:tokenOf(login)||initToken,info:login.info||login.data?.user||{}};
    }
  }catch(e){
    console.log("AuthLX login:",e.message);
  }

  try{
    const reg=await authlx("register",{...base(hwid),username:license,password:license,license_key:license,license,...(initToken?{session_token:initToken}:{})});
    if(String(reg?.status||"").toLowerCase()==="success"){
      return {valid:true,stage:"register",message:reg.message||"License activated",session_token:tokenOf(reg)||initToken,info:reg.info||reg.data?.user||{}};
    }
    throw new Error(reg?.message||"Registration failed");
  }catch(e){
    console.log("AuthLX register:",e.message);
    return {valid:false,stage:"register",message:e.message||"License registration failed"};
  }
}

// Atomically bind a license to exactly one extension installation.
// The binding is persistent in PostgreSQL, so Render restarts do not reset it.
async function bindOnePc(license, installationId){
  const hash=licenseHash(license);
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const existing=await client.query(
      "SELECT installation_id FROM gmc_license_bindings WHERE license_hash=$1 FOR UPDATE",
      [hash]
    );

    if(existing.rowCount){
      const bound=existing.rows[0].installation_id;
      if(bound!==installationId){
        await client.query("ROLLBACK");
        return {ok:false,code:"LICENSE_BOUND",message:"License is already bound to another PC"};
      }
      await client.query(
        "UPDATE gmc_license_bindings SET last_seen_at=NOW() WHERE license_hash=$1",
        [hash]
      );
      await client.query("COMMIT");
      return {ok:true,existing:true};
    }

    await client.query(
      "INSERT INTO gmc_license_bindings (license_hash,installation_id) VALUES ($1,$2)",
      [hash,installationId]
    );
    await client.query("COMMIT");
    return {ok:true,existing:false};
  }catch(e){
    try{await client.query("ROLLBACK");}catch{}
    throw e;
  }finally{
    client.release();
  }
}

async function checkBinding(license, installationId){
  const hash=licenseHash(license);
  const r=await pool.query(
    "SELECT installation_id FROM gmc_license_bindings WHERE license_hash=$1",
    [hash]
  );
  if(!r.rowCount) return {ok:false,code:"NOT_BOUND",message:"License is not activated on this installation"};
  if(r.rows[0].installation_id!==installationId) return {ok:false,code:"LICENSE_BOUND",message:"License is bound to another PC"};
  await pool.query("UPDATE gmc_license_bindings SET last_seen_at=NOW() WHERE license_hash=$1",[hash]);
  return {ok:true};
}

app.get("/",(_,res)=>res.json({ok:true,service:"gmc-authlx",binding:"1-license-1-installation"}));
app.get("/health",(_,res)=>res.json({ok:true}));

app.post("/api/license",async(req,res)=>{
  const license=String(req.body?.license||"").trim();
  const hwid=String(req.body?.hwid||"").trim();
  if(!license||!hwid) return res.status(400).json({valid:false,message:"License and installation ID are required"});

  try{
    // If this license was already claimed by another installation, stop before
    // contacting AuthLX so the second PC can never take ownership.
    const current=await checkBinding(license,hwid);
    if(!current.ok && current.code==="LICENSE_BOUND"){
      return res.status(409).json({valid:false,message:current.message});
    }

    const result=await authenticate(license,hwid);
    if(!result.valid) return res.status(403).json(result);

    const bound=await bindOnePc(license,hwid);
    if(!bound.ok) return res.status(409).json({valid:false,message:bound.message});

    return res.json({...result,binding:"1-license-1-installation"});
  }catch(e){
    console.error("activation:",e);
    return res.status(502).json({valid:false,message:e.message||"License service error"});
  }
});

app.post("/api/check",async(req,res)=>{
  const license=String(req.body?.license||"").trim();
  const hwid=String(req.body?.hwid||"").trim();
  if(!license||!hwid) return res.status(400).json({valid:false,message:"License and installation ID are required"});

  try{
    const binding=await checkBinding(license,hwid);
    if(!binding.ok) return res.status(403).json({valid:false,message:binding.message});

    const init=await initialize();
    const initToken=tokenOf(init);
    const login=await authlx("login",{...base(hwid),username:license,password:license,...(initToken?{session_token:initToken}:{})});
    if(String(login?.status||"").toLowerCase()==="success"){
      return res.json({valid:true,session_token:tokenOf(login)||initToken,message:login.message||"License valid"});
    }
    return res.status(403).json({valid:false,message:login?.message||"License is no longer valid"});
  }catch(e){
    console.log("AuthLX recheck:",e.message);
    return res.status(403).json({valid:false,message:e.message||"License validation failed"});
  }
});

const port=process.env.PORT||3000;
initDb().then(()=>{
  app.listen(port,()=>console.log(`GMC AuthLX proxy listening on ${port} (1-license/1-installation)`));
}).catch(e=>{
  console.error("Database initialization failed:",e);
  process.exit(1);
});
