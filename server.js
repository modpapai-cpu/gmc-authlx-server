import express from "express";
import crypto from "node:crypto";

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

app.get("/",(_,res)=>res.json({ok:true,service:"gmc-authlx"}));
app.get("/health",(_,res)=>res.json({ok:true}));
app.get("/api/version",(_,res)=>res.json({
  ok:true,
  latest_version:LATEST_VERSION,
  minimum_version:MIN_VERSION,
  update_url:UPDATE_URL,
  message:"Update required"
}));

app.post("/api/license",async(req,res)=>{
  const license=String(req.body?.license||"").trim();
  const hwid=String(req.body?.hwid||"").trim();
  if(!license||!hwid) return res.status(400).json({valid:false,message:"License and installation ID are required"});
  try{
    const result=await authenticate(license,hwid);
    if(result.valid) return res.json(result);
    return res.status(403).json(result);
  }catch(e){
    console.error("activation:",e);
    return res.status(502).json({valid:false,message:e.message||"License service error"});
  }
});

// Re-check by repeating the SDK's login path with the same installation HWID.
// This avoids the unavailable /check_ban route while still failing closed when AuthLX rejects the session/device.
app.post("/api/check",async(req,res)=>{
  const license=String(req.body?.license||"").trim();
  const hwid=String(req.body?.hwid||"").trim();
  if(!license||!hwid) return res.status(400).json({valid:false,message:"License and installation ID are required"});
  try{
    const init=await initialize();
    const initToken=tokenOf(init);
    const login=await authlx("login",{...base(hwid),username:license,password:license,...(initToken?{session_token:initToken}:{})});
    if(String(login?.status||"").toLowerCase()==="success") return res.json({valid:true,session_token:tokenOf(login)||initToken,message:login.message||"License valid"});
    return res.status(403).json({valid:false,message:login?.message||"License is no longer valid"});
  }catch(e){
    console.log("AuthLX recheck:",e.message);
    return res.status(403).json({valid:false,message:e.message||"License validation failed"});
  }
});

const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`GMC AuthLX proxy listening on ${port}`));
