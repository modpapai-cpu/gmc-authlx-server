import express from "express";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "20kb" }));
app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type");
  if(req.method==="OPTIONS") return res.sendStatus(204);
  next();
});

const AUTHLX_URL=(process.env.AUTHLX_URL||"https://api.authlx.com/api/v2/client/").replace(/\/$/,"");
const NAME=process.env.AUTHLX_NAME||"SteamTool";
const OWNERID=process.env.AUTHLX_OWNERID||"c90b8793-0c53-4d57-b8ad-5edaf6dcf0db";
const VERSION=process.env.AUTHLX_VERSION||"1.0";
const SECRET=process.env.AUTHLX_SECRET||"";

function nonce(n=32){return crypto.randomBytes(n/2).toString("hex");}
function hmac(key,msg){return crypto.createHmac("sha256",key).update(msg,"utf8").digest("hex");}
function canonical(v){
  if(v===null)return"null";
  if(Array.isArray(v))return"["+v.map(canonical).join(",")+"]";
  if(typeof v==="object")return"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}";
  if(typeof v==="string")return JSON.stringify(v);
  if(typeof v==="boolean"||typeof v==="number")return String(v);
  return JSON.stringify(String(v));
}

async function authlx(endpoint,payload){
  const requestNonce=nonce();
  const r=await fetch(`${AUTHLX_URL}/${endpoint}`,{
    method:"POST",
    headers:{
      "Content-Type":"application/json; charset=UTF-8",
      "Accept":"application/json",
      "User-Agent":`AuthLX-SDK-Render/1.0 (${NAME})`,
      "X-Request-Nonce":requestNonce
    },
    body:JSON.stringify(payload)
  });
  const text=await r.text();
  let data=null; try{data=JSON.parse(text);}catch{}
  if(!r.ok){
    const e=new Error(`AuthLX HTTP ${r.status}: ${data?.message||text||"request failed"}`);
    e.status=r.status;e.data=data;throw e;
  }
  if(!data)throw new Error("Invalid AuthLX JSON response");

  const sig=r.headers.get("x-response-sig");
  const nonceHeader=r.headers.get("x-response-nonce");
  if(SECRET&&sig&&nonceHeader){
    if(nonceHeader.toLowerCase()!==requestNonce.toLowerCase())throw new Error("AuthLX response nonce mismatch");
    const expected=hmac(SECRET,canonical(data)+":"+requestNonce);
    const a=Buffer.from(expected.toLowerCase()),b=Buffer.from(sig.toLowerCase());
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b))throw new Error("AuthLX response signature mismatch");
  }
  return data;
}

function payload(hwid,extra={}){return{app_id:OWNERID,name:NAME,version:VERSION,hwid:hwid||"",...extra};}
function tokenOf(x){return x?.session_token||x?.data?.token||x?.token||"";}

async function init(){
  const r=await authlx("init",{app_id:OWNERID,name:NAME,version:VERSION});
  if(String(r?.status||"").toLowerCase()!=="success")throw new Error(r?.message||"AuthLX initialization failed");
  return r;
}

app.get("/",(_,res)=>res.json({ok:true,service:"gmc-authlx"}));
app.get("/health",(_,res)=>res.json({ok:true}));

// Initial activation. Unused license: login normally fails, then register consumes the voucher.
// Already-used license: login authenticates the existing account. The supplied installation ID is
// sent as HWID, so AuthLX can enforce the same HWID on subsequent activations.
app.post("/api/license",async(req,res)=>{
  const license=String(req.body?.license||"").trim();
  const hwid=String(req.body?.hwid||"").trim();
  if(!license||!hwid)return res.status(400).json({valid:false,message:"License and installation ID are required"});

  try{
    const boot=await init();
    const bootToken=tokenOf(boot);

    try{
      const login=await authlx("login",payload(hwid,{
        username:license,password:license,
        ...(bootToken?{session_token:bootToken}:{})
      }));
      if(String(login?.status||"").toLowerCase()==="success"){
        const token=tokenOf(login)||bootToken;
        if(token){
          const banned=await authlx("check_ban",payload(hwid,{session_token:token}));
          if(banned?.is_banned||String(banned?.status||"").toLowerCase()==="banned")
            return res.status(403).json({valid:false,message:"License is banned"});
        }
        return res.json({valid:true,token,message:login?.message||"License valid"});
      }
    }catch(e){console.log("AuthLX login:",e.message);}

    try{
      const reg=await authlx("register",payload(hwid,{
        username:license,password:license,license_key:license,license,
        ...(bootToken?{session_token:bootToken}:{})
      }));
      if(String(reg?.status||"").toLowerCase()==="success"){
        // AuthLX may return a successful registration without an auth token.
        // The official SDK then logs in again, so mirror that behavior here.
        let token=tokenOf(reg);
        if(token){
          const banned=await authlx("check_ban",payload(hwid,{session_token:token}));
          if(banned?.is_banned||String(banned?.status||"").toLowerCase()==="banned")
            return res.status(403).json({valid:false,message:"License is banned"});
          return res.json({valid:true,token,message:reg?.message||"License activated"});
        }

        try{
          const relogin=await authlx("login",payload(hwid,{username:license,password:license}));
          if(String(relogin?.status||"").toLowerCase()==="success"){
            token=tokenOf(relogin);
            if(token){
              const banned=await authlx("check_ban",payload(hwid,{session_token:token}));
              if(banned?.is_banned||String(banned?.status||"").toLowerCase()==="banned")
                return res.status(403).json({valid:false,message:"License is banned"});
              return res.json({valid:true,token,message:reg?.message||"License activated"});
            }
          }
        }catch(e){
          console.log("AuthLX post-register login:",e.message);
        }
      }
    }catch(e){console.log("AuthLX register:",e.message);}

    return res.status(403).json({valid:false,message:"License invalid or not accepted"});
  }catch(e){
    console.error(e);
    return res.status(502).json({valid:false,message:e.message||"License service error"});
  }
});

// Revalidation uses the existing AuthLX session token and check_ban.
// If the session has been revoked/banned, the extension fails closed.
app.post("/api/check",async(req,res)=>{
  const token=String(req.body?.token||"").trim();
  const hwid=String(req.body?.hwid||"").trim();
  if(!token||!hwid)return res.status(400).json({valid:false,message:"Session token and installation ID are required"});
  try{
    const boot=await init();
    const result=await authlx("check_ban",payload(hwid,{session_token:token}));
    if(result?.is_banned||String(result?.status||"").toLowerCase()==="banned")
      return res.status(403).json({valid:false,message:"License is banned or revoked"});
    // A successful, non-banned response is accepted as a live session.
    if(String(result?.status||"success").toLowerCase()==="success"||result?.is_banned===false)
      return res.json({valid:true});
    return res.status(403).json({valid:false,message:result?.message||"License session is not valid"});
  }catch(e){
    console.error("check:",e.message);
    return res.status(403).json({valid:false,message:"License validation failed"});
  }
});

const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`GMC AuthLX proxy listening on ${port}`));
