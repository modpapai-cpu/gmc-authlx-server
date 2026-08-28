import express from "express";
import crypto from "node:crypto";

const app=express();
app.use(express.json({limit:"20kb"}));
app.use((req,res,next)=>{res.setHeader("Access-Control-Allow-Origin","*");res.setHeader("Access-Control-Allow-Methods","POST,GET,OPTIONS");res.setHeader("Access-Control-Allow-Headers","Content-Type");if(req.method==="OPTIONS")return res.sendStatus(204);next();});

const AUTHLX_URL=(process.env.AUTHLX_URL||"https://api.authlx.com/api/v2/client/").replace(/\/$/,"");
const NAME=process.env.AUTHLX_NAME||"SteamTool";
const OWNERID=process.env.AUTHLX_OWNERID||"c90b8793-0c53-4d57-b8ad-5edaf6dcf0db";
const VERSION=process.env.AUTHLX_VERSION||"1.0";
const SECRET=process.env.AUTHLX_SECRET||"";

function nonce(n=32){return crypto.randomBytes(n/2).toString("hex");}
function hmac(key,msg){return crypto.createHmac("sha256",key).update(msg,"utf8").digest("hex");}
function canonical(v){
  if(v===null) return "null";
  if(Array.isArray(v)) return "["+v.map(canonical).join(",")+"]";
  if(typeof v==="object") return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}";
  if(typeof v==="string") return JSON.stringify(v);
  if(typeof v==="boolean"||typeof v==="number") return String(v);
  return JSON.stringify(String(v));
}
async function authlx(endpoint,payload){
  const requestNonce=nonce(32);
  const r=await fetch(`${AUTHLX_URL}/${endpoint}`,{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json","User-Agent":`AuthLX-SDK-Render/1.0 (${NAME})`,`X-Request-Nonce`:requestNonce},body:JSON.stringify(payload)});
  const text=await r.text();
  if(!r.ok) throw new Error(`AuthLX HTTP ${r.status}`);
  let data; try{data=JSON.parse(text)}catch{throw new Error("Invalid AuthLX response")}
  const sig=r.headers.get("x-response-sig"), rh=r.headers.get("x-response-nonce");
  if(SECRET && sig && rh){
    if(rh.toLowerCase()!==requestNonce.toLowerCase()) throw new Error("AuthLX response nonce mismatch");
    const expected=hmac(SECRET,canonical(data)+":"+requestNonce);
    if(!crypto.timingSafeEqual(Buffer.from(expected.toLowerCase()),Buffer.from(sig.toLowerCase()))) throw new Error("AuthLX response signature mismatch");
  }
  return data;
}

app.get("/health",(_,res)=>res.json({ok:true}));
app.post("/api/license",async(req,res)=>{
  const {license,hwid}=req.body||{};
  if(!license) return res.status(400).json({valid:false,message:"License key is required"});
  try{
    const init=await authlx("init",{app_id:OWNERID,name:NAME,version:VERSION});
    if(String(init.status||"").toLowerCase()!=="success") return res.status(403).json({valid:false,message:init.message||"AuthLX initialization failed"});
    const payload={app_id:OWNERID,name:NAME,version:VERSION,license:String(license).trim(),hwid:hwid||""};
    if(init.session_token) payload.session_token=init.session_token;
    const result=await authlx("license",payload);
    const valid=String(result.status||"").toLowerCase()==="success";
    const info=result.user_data||result.user||result.info||{};
    return res.status(valid?200:403).json({valid,message:result.message|| (valid?"License valid":"License invalid"),expires:info.expiration_date||info.expires||info.expiry||"",session_token:valid?(result.session_token||""):undefined});
  }catch(e){console.error(e);return res.status(502).json({valid:false,message:e.message||"License service error"});}
});
const port=process.env.PORT||3000; app.listen(port,()=>console.log(`GMC AuthLX proxy listening on ${port}`));
