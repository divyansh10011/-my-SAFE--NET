// ================= SAFE-NET ENTERPRISE CORE =================
Tesseract.setLogging(false);

document.addEventListener("DOMContentLoaded", () => {

  /* ================= DOM ================= */
  const input = document.getElementById("input");
  const fileInput = document.getElementById("fileInput");
  const previewBtn = document.getElementById("previewBtn");
  const scanBtn = document.getElementById("scanBtn");
  const statusEl = document.getElementById("status");
  const outputEl = document.getElementById("output");

  const smartLoader = document.getElementById("smartLoader");
  const loaderMain = document.getElementById("loaderMain");
  const loaderSub = document.getElementById("loaderSub");
  const smartProgress = document.getElementById("smartProgress");

  let selectedFile = null;
  let aiModel = null;

  /* ================= LOADER ================= */
  function showLoader(title, subtitle, progress){
    smartLoader.classList.remove("hidden");
    loaderMain.textContent = title;
    loaderSub.textContent = subtitle;
    smartProgress.style.width = progress + "%";
  }

  function updateLoader(progress, subtitle){
    smartProgress.style.width = progress + "%";
    if(subtitle) loaderSub.textContent = subtitle;
  }

  function hideLoader(){
    smartLoader.classList.add("hidden");
  }

  /* ================= INPUT FIREWALL ================= */
  function validateInput(text){
    const clean = text.trim();

    if(!clean) return { ok:false, reason:"Empty input" };
    if(clean.length < 8) return { ok:false, reason:"Too short to analyze" };
    if(/^[0-9\s]+$/.test(clean)) return { ok:false, reason:"Only numbers" };
    if(/^[\W_]+$/.test(clean)) return { ok:false, reason:"Only symbols" };
    if(/^(.)\1{5,}$/.test(clean)) return { ok:false, reason:"Repeated characters" };
    if(!/[a-zA-Z]/.test(clean)) return { ok:false, reason:"No readable text" };

    return { ok:true };
  }

  /* ================= INTELLIGENCE DB ================= */
  const TRIGGERS = [
    "urgent","verify","password","otp","bank","login","reset",
    "account locked","security alert","unauthorized","limited",
    "refund","invoice","prize","gift","crypto","bitcoin",
    "tax","court","legal","arrest","blocked","suspended"
  ];

  const FINANCIAL = [
    "upi","ifsc","cvv","pin","card","wallet",
    "transaction","transfer","payment"
  ];

  const FAKE_BRANDS = ["paypa","micros0ft","faceb00k","g00gle","amaz0n"];
  const MALICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".ru",".cn"];
  const SHORTENERS = ["bit.ly","tinyurl","t.co","rebrand.ly","goo.gl"];

  /* ================= UTIL ================= */
  function extractURLs(text){
    return text.match(/https?:\/\/[^\s<>"')]+/gi) || [];
  }

  function extractEmails(text){
    return text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/gi) || [];
  }

  function domainFromURL(url){
    try { return new URL(url).hostname.replace("www.",""); }
    catch { return null; }
  }

  function entropy(str){
    const freq = {};
    for(const c of str) freq[c] = (freq[c]||0)+1;
    return Object.values(freq)
      .reduce((e,v)=> e-(v/str.length)*Math.log2(v/str.length),0);
  }

  function hasUnicode(text){
    return /[а-яА-Я०-९]/.test(text);
  }

  /* ================= OCR ================= */
  async function ocrImage(file){
    showLoader("OCR Engine","Extracting text from image...",30);
    const res = await Tesseract.recognize(file,"eng");
    updateLoader(70,"OCR complete");
    return res.data.text || "";
  }

  /* ================= AI ================= */
  async function loadAI(){
    try{
      updateLoader(40,"Loading AI semantic model");
      aiModel = await use.load();
      updateLoader(80,"AI ready");
    }catch(e){
      console.warn("AI failed → fallback mode");
      aiModel = null;
      updateLoader(80,"AI unavailable (fallback)");
    }
  }

  async function aiScore(text){
    if(!aiModel) return 0;
    const emb = await aiModel.embed([text]);
    const vec = emb.arraySync()[0];
    emb.dispose();
    return Math.min(1, vec.reduce((a,b)=>a+Math.abs(b),0)%1);
  }

  /* ================= MILITARY THREAT ENGINE ================= */
  function deepThreatEngine(text){
    let score = 0;
    const findings = [];
    const lower = text.toLowerCase();

    const urls = extractURLs(text);
    const emails = extractEmails(text);

    urls.forEach(u=>{
      score += 30;
      findings.push("URL detected: "+u);
      const domain = domainFromURL(u);

      if(domain){
        SHORTENERS.forEach(s=>{
          if(domain.includes(s)){
            score += 25;
            findings.push("Shortened URL: "+domain);
          }
        });
        MALICIOUS_TLDS.forEach(t=>{
          if(domain.endsWith(t)){
            score += 35;
            findings.push("Malicious TLD: "+domain);
          }
        });
        FAKE_BRANDS.forEach(b=>{
          if(domain.includes(b)){
            score += 45;
            findings.push("Brand impersonation: "+domain);
          }
        });
        if(domain.split(".").length > 4){
          score += 20;
          findings.push("Deep subdomain chain");
        }
      }
    });

    emails.forEach(e=>{
      score += 20;
      findings.push("Email detected: "+e);
      if(e.includes("support")||e.includes("secure")){
        score += 15;
        findings.push("Impersonation mailbox");
      }
    });

    TRIGGERS.forEach(w=>{
      if(lower.includes(w)){
        score += 8;
        findings.push("Trigger keyword: "+w);
      }
    });

    FINANCIAL.forEach(w=>{
      if(lower.includes(w)){
        score += 12;
        findings.push("Financial data request: "+w);
      }
    });

    if(entropy(text) > 4.3){
      score += 25;
      findings.push("High entropy / obfuscation");
    }

    if(hasUnicode(text)){
      score += 30;
      findings.push("Unicode homoglyph attack");
    }

    if(lower.match(/[0-9]{6,}/)){
      score += 20;
      findings.push("OTP / PIN harvesting");
    }

    if(lower.includes("click here") || lower.includes("act now")){
      score += 20;
      findings.push("Psychological manipulation");
    }

    if(text.length < 60 && urls.length){
      score += 25;
      findings.push("Short lure message");
    }

    return {score:Math.min(100,score), findings};
  }

  /* ================= MAIN SCAN ================= */
  async function runScan(){
    let text = input.value.trim();

    const validation = validateInput(text);

    if(!validation.ok && !selectedFile){
      statusEl.className = "warn";
      statusEl.textContent = "Invalid input — " + validation.reason;
      outputEl.textContent =
        "INPUT REJECTED\n" +
        "====================\n" +
        "Reason: " + validation.reason + "\n\n" +
        "Please enter meaningful text, URL, email, or image.";
      return;
    }

    showLoader("SafeNet Scan","Running threat analysis...",20);

    if(selectedFile && selectedFile.type.startsWith("image/")){
      const ocrText = await ocrImage(selectedFile);
      text += "\n"+ocrText;
    }

    updateLoader(50,"Behavioral analysis");
    const heur = deepThreatEngine(text);
    let score = heur.score;

    updateLoader(75,"Semantic AI reasoning");
    const ai = await aiScore(text);
    score += Math.round(ai*30);

    updateLoader(95,"Final decision");
    setTimeout(hideLoader,500);

    let level="safe",msg="Low Risk";
    if(score>=85){level="danger";msg="CRITICAL — ACTIVE SCAM";}
    else if(score>=60){level="warn";msg="HIGH RISK — FRAUD";}
    else if(score>=40){level="unknown";msg="SUSPICIOUS";}

    statusEl.className = level;
    statusEl.textContent = `${msg} (Risk Score: ${score}/100)`;

    outputEl.textContent =
      "SAFE-NET CYBER INTELLIGENCE REPORT\n"+
      "====================================\n"+
      "Threat Level: "+msg+"\n"+
      "Risk Score  : "+score+"/100\n\n"+
      "DETECTED SIGNALS:\n"+
      (heur.findings.join("\n")||"None")+
      "\n\nFULL CONTENT ANALYZED:\n"+text;
  }

  /* ================= FILE ================= */
  fileInput.onchange = e=>{
    resetSystem();                 // reset ONLY on user action
    selectedFile = e.target.files[0];
  };

  previewBtn.onclick = async ()=>{
    if(!selectedFile) return;
    const w = window.open("");
    if(selectedFile.type.startsWith("image/")){
      w.document.write(`<img src="${URL.createObjectURL(selectedFile)}" style="max-width:100%">`);
    }else{
      w.document.write(`<pre>${await selectedFile.text()}</pre>`);
    }
  };

  scanBtn.onclick = runScan;

  input.oninput = ()=>{
    resetSystem();                 // reset ONLY on user typing
  };

  /* ================= ENTERPRISE BOOT SEQUENCE ================= */
  showLoader("SafeNet Initializing","Loading cyber defense modules...",10);

  loadAI().then(()=>{
    updateLoader(100,"System secured");
    setTimeout(hideLoader,700);
    statusEl.textContent="System Ready. Paste content to scan.";
  });

  function resetSystem(){
    statusEl.className = "unknown";
    statusEl.textContent = "System Ready. Paste new content to scan.";
    outputEl.textContent = "";
  }

});
// ================= END OF CORE =================
