import React, { useState, useEffect, useCallback } from "react";
import {
  ShieldCheck, KeyRound, Lock, Eye, Database, Filter, Braces, Plus, Check,
  GitCompare, UserRound, Fingerprint, Receipt, Cake, Syringe, Activity, Smile,
  Plane, HeartPulse, Landmark, Umbrella, Bus, AtSign, Layers, ScanLine,
  ChevronDown, X, ShieldAlert, Link2,
} from "lucide-react";
import * as api from "./api";

/**
 * DalanID - contextual profile disclosure.
 *
 * This component no longer decides what may be disclosed. Every value it shows
 * arrives from the Django service, which verifies a signed Context-Key and
 * projects the citizen record through the context that key names. The browser
 * holds no signing secret and cannot widen its own view: requesting a context
 * it is not authorised for returns 401 and the interface renders the refusal.
 *
 * Icons and tier colours remain client-side because they are presentation,
 * not policy. Everything that constitutes policy - which fields a context may
 * see, whether a party may invoke it, whether a value is disclosed raw or
 * derived - is server state.
 */

const CITIZEN = "maria-da-costa";

// Presentation only. An attribute with no entry falls back to a generic icon,
// so a field added server-side still renders without a client change.
const ATTR_ICONS = {
  legal_name: UserRound, passport: Fingerprint, tax_id: Receipt, dob: Cake,
  vaccination: Syringe, risk: Activity, vid_token: KeyRound, nickname: Smile,
};
const CTX_ICONS = {
  immigration: Plane, public_health: HeartPulse, banking: Landmark,
  insurance: Umbrella, public_service: Bus, social: AtSign,
  "context-administration": Layers, __full__: Database,
};

const FULL_CONTEXT = {
  slug: "__full__", name: "Full record", tier: "Unprotected",
  purpose: "Unprotected baseline, shown for comparison only.",
  permitted: [], field_count: 0, grant_holders: ["baseline"],
};

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
.dz *{box-sizing:border-box}
.dz{--ink:#0C2230;--ink2:#16384a;--paper:#E8EEEC;--card:#fff;--line:#D7E0DD;--gold:#A9802A;--goldsoft:#F4EBD2;--green:#2C7A58;--greensoft:#E2EFE9;--muted:#5f6f77;--redact:#162530;
font-family:'Inter',system-ui,sans-serif;color:var(--ink);min-height:100vh;
background:radial-gradient(900px 420px at 50% -160px,#fff 0%,rgba(255,255,255,0) 72%),var(--paper);}
.dz-wrap{max-width:1060px;margin:0 auto;padding:22px 18px 60px}
.dz-head{position:relative;overflow:hidden;border-radius:22px;padding:26px 24px;color:#EAF1EE;border:1px solid #08161f;
background:radial-gradient(560px 240px at 88% -30%,rgba(169,128,42,.26),transparent 70%),linear-gradient(135deg,var(--ink) 0%,var(--ink2) 100%);
box-shadow:0 22px 48px -26px rgba(12,34,48,.6)}
.dz-head::after{content:"";position:absolute;top:-70px;right:-50px;width:230px;height:230px;border-radius:50%;pointer-events:none;
background:radial-gradient(closest-side,rgba(169,128,42,.14),transparent 78%)}
.dz-htop{display:flex;align-items:center;gap:14px;position:relative;z-index:1}
.dz-seal{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;width:54px;height:54px;border-radius:50%;flex:none;
background:radial-gradient(circle at 36% 30%,#1d4356,#0b2029);border:1.5px solid var(--gold);color:var(--gold);
box-shadow:inset 0 0 0 4px rgba(169,128,42,.16),0 5px 16px -7px rgba(0,0,0,.55)}
.dz-title{font-family:'Fraunces',Georgia,serif;font-weight:600;font-size:30px;letter-spacing:-.01em;line-height:1.05;margin:0}
.dz-sub{font-size:13px;color:#9fb4b1;margin-top:2px}
.dz-badge{margin-left:auto;font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--gold);
border:1px solid rgba(169,128,42,.5);border-radius:999px;padding:5px 10px;background:rgba(169,128,42,.08);white-space:nowrap}
.dz-lede{position:relative;z-index:1;margin:16px 0 0;max-width:640px;font-size:13.5px;line-height:1.6;color:#cdddd8}
.dz-pipe{position:relative;z-index:1;margin-top:18px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;
padding-top:16px;border-top:1px solid rgba(255,255,255,.12)}
.dz-step{display:flex;align-items:center;gap:7px;font-size:12px;color:#bcd0cc}
.dz-step b{font-weight:600;color:#eef4f2}
.dz-step svg{color:var(--gold)}
.dz-arrow{color:rgba(255,255,255,.3);font-size:12px}
.dz-keyrow{display:flex;align-items:center;gap:8px;margin-top:12px;flex-wrap:wrap;position:relative;z-index:1}
.dz-keyrow span{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#9fb4b1}
.dz-key{font-family:'JetBrains Mono',monospace;font-size:12px;color:#0c2230;background:linear-gradient(180deg,#f5ecd2,#e9d7a8);
border:1px solid var(--gold);border-radius:7px;padding:4px 9px;font-weight:500}
.dz-secrow{display:flex;align-items:baseline;justify-content:space-between;margin:26px 0 10px}
.dz-eyebrow{font-size:11px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.dz-chips{display:flex;flex-wrap:wrap;gap:8px}
.dz-chip{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);background:var(--card);color:#22414c;
border-radius:12px;padding:9px 12px;font-size:13.5px;font-weight:500;cursor:pointer;transition:all .15s ease}
.dz-chip:hover{border-color:#9fb1ac;transform:translateY(-1px)}
.dz-chip svg{color:#94a6a2}
.dz-chip .ct{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);background:#eef2f1;border-radius:6px;padding:1px 6px}
.dz-chip.on{background:var(--ink);border-color:var(--ink);color:#fff;box-shadow:0 10px 22px -14px rgba(12,34,48,.8)}
.dz-chip.on svg{color:var(--gold)}
.dz-chip.on .ct{background:rgba(255,255,255,.14);color:#f4ead2}
.dz-chip.new{border-style:dashed;color:var(--muted)}
.dz-chip.new:hover{border-color:var(--gold);color:var(--gold)}
.dz-ctxbar{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
.dz-selwrap{position:relative;flex:1;min-width:240px}
.dz-sellead{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:#7d8d88;pointer-events:none}
.dz-selchev{position:absolute;right:12px;top:50%;transform:translateY(-50%);color:#7d8d88;pointer-events:none}
.dz-ctxsel{width:100%;appearance:none;-webkit-appearance:none;border:1px solid var(--line);background:var(--card);
border-radius:12px;padding:12px 38px;font-size:14px;font-weight:600;color:var(--ink);font-family:inherit;cursor:pointer;
box-shadow:0 8px 22px -18px rgba(12,34,48,.5)}
.dz-ctxsel:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(169,128,42,.16)}
.dz-btn{display:inline-flex;align-items:center;gap:7px;border-radius:11px;padding:9px 13px;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s}
.dz-btn.ghost{background:var(--card);border:1px solid var(--line);color:#22414c}
.dz-btn.ghost:hover{border-color:#9fb1ac}
.dz-btn.ghost.on{background:var(--ink);border-color:var(--ink);color:#fff}
.dz-btn.gold{background:var(--gold);border:1px solid var(--gold);color:#fff}
.dz-btn.gold:hover{filter:brightness(1.06)}
.dz-btn.gold:disabled{background:#cbd5d2;border-color:#cbd5d2;cursor:not-allowed}
.dz-grid{display:grid;gap:16px;grid-template-columns:1fr;align-items:start}
@media(min-width:900px){.dz-grid{grid-template-columns:1.35fr 1fr}}
.dz-cmpgrid{display:grid;gap:16px;grid-template-columns:1fr}
@media(min-width:760px){.dz-cmpgrid{grid-template-columns:1fr 1fr}}
.dz-pickrow{display:grid;gap:12px;grid-template-columns:1fr 1fr;margin-bottom:12px}
.dz-select,.dz-input{width:100%;border:1px solid var(--line);background:var(--card);border-radius:10px;padding:9px 11px;font-size:13.5px;font-family:inherit;color:var(--ink);outline:none}
.dz-select:focus,.dz-input:focus{border-color:var(--gold);box-shadow:0 0 0 3px rgba(169,128,42,.16)}
/* credential card */
.dz-cred{border-radius:18px;overflow:hidden;background:var(--card);border:1px solid var(--line);box-shadow:0 16px 40px -28px rgba(12,34,48,.5)}
.dz-credtop{position:relative;overflow:hidden;padding:16px 18px;color:#eaf1ee;background:linear-gradient(135deg,#13303f,#0c2230)}
.dz-credtop.full{background:linear-gradient(135deg,#5a2230,#3a1620)}
.dz-credtop .row1{display:flex;align-items:center;gap:9px;position:relative;z-index:1;flex-wrap:wrap}
.dz-credtop .nm{font-family:'Fraunces',serif;font-weight:600;font-size:18px}
.dz-tier{font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;border-radius:999px;padding:3px 9px;border:1px solid}
.dz-holder{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px dashed var(--line);background:linear-gradient(180deg,#fbfcfb,#fff)}
.dz-av{width:46px;height:46px;border-radius:12px;flex:none;overflow:hidden;display:flex;align-items:center;justify-content:center;font-family:'Fraunces',serif;font-weight:600;font-size:20px;line-height:1;
background:linear-gradient(160deg,var(--goldsoft),#e7d3a3);color:#6e521b;border:1px solid var(--gold)}
.dz-av.protected{background:#eef1f0;color:#aab6b2;border-color:var(--line);box-shadow:inset 0 0 0 3px rgba(255,255,255,.6)}
.dz-hname{font-weight:600;font-size:15px}
.dz-hmeta{font-size:12px;color:var(--muted)}
.dz-meter{padding:12px 18px;border-bottom:1px solid var(--line)}
.dz-meterhead{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:6px}
.dz-meterhead b{color:var(--ink);font-weight:600}
.dz-track{height:8px;border-radius:999px;background:#e7ecea;overflow:hidden}
.dz-fill{height:100%;border-radius:999px;transition:width .45s cubic-bezier(.2,.7,.2,1)}
.dz-rows{padding:6px 8px 10px}
.dz-row{display:flex;align-items:center;gap:12px;padding:9px 10px;border-radius:11px;animation:dzFade .4s both}
.dz-row+.dz-row{margin-top:2px}
.dz-ricon{width:34px;height:34px;border-radius:9px;flex:none;display:flex;align-items:center;justify-content:center}
.dz-row.on .dz-ricon{background:var(--greensoft);color:var(--green)}
.dz-row.off .dz-ricon{background:#eef1f0;color:#aab6b2}
.dz-rlabel{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.dz-rval{font-size:14px;font-weight:600;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dz-rmid{min-width:0;flex:1}
.dz-redact{position:relative;height:18px;border-radius:5px;margin-top:3px;overflow:hidden;
background:repeating-linear-gradient(45deg,var(--redact) 0 7px,#22323d 7px 14px)}
.dz-redact span{position:absolute;inset:0;display:flex;align-items:center;gap:5px;justify-content:flex-start;padding-left:8px;
color:#b9c6cb;font-size:9.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}
.dz-rtag{flex:none;font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.dz-row.on .dz-rtag{color:var(--green)}
.dz-row.off .dz-rtag{color:#bcc6c2}
/* json */
.dz-json{border-radius:18px;overflow:hidden;background:#0c2230;border:1px solid #081822;box-shadow:0 16px 40px -28px rgba(12,34,48,.6)}
.dz-jtop{display:flex;align-items:center;gap:8px;padding:11px 14px;border-bottom:1px solid rgba(255,255,255,.08);color:#cdddd8;font-size:12.5px;font-weight:600}
.dz-jtop svg{color:var(--gold)}
.dz-200{margin-left:auto;font-size:10px;font-weight:700;color:#86d9b3;background:rgba(46,125,91,.2);border-radius:5px;padding:2px 7px}
.dz-json pre{margin:0;padding:14px;max-height:430px;overflow:auto;font-family:'JetBrains Mono',monospace;font-size:11.5px;line-height:1.65;color:#dbe7e3}
.dz-jnote{padding:9px 14px;border-top:1px solid rgba(255,255,255,.07);font-size:11px;color:#8aa09b}
.dz-jk{color:#9fd0bd}.dz-js{color:#e7c98a}.dz-jn{color:#f0a39a}
.dz-form{border:1px solid var(--gold);background:linear-gradient(180deg,#fbf6ea,#fff);border-radius:18px;padding:18px}
.dz-formnote{font-size:12px;color:#8a6e2f;margin:2px 0 14px}
.dz-flabel{font-size:11px;font-weight:600;color:var(--muted);margin-bottom:5px;display:block}
.dz-fgrid{display:grid;gap:12px;grid-template-columns:1fr}
@media(min-width:640px){.dz-fgrid{grid-template-columns:1fr 1fr}}
.dz-fields{display:grid;gap:7px;grid-template-columns:1fr;margin-top:6px}
@media(min-width:640px){.dz-fields{grid-template-columns:1fr 1fr}}
.dz-fopt{display:flex;align-items:center;gap:9px;border:1px solid var(--line);background:#fff;border-radius:10px;padding:9px 11px;font-size:13.5px;color:var(--muted);cursor:pointer;text-align:left}
.dz-fopt.on{border-color:var(--gold);color:var(--ink)}
.dz-box{width:17px;height:17px;border-radius:5px;border:1px solid #c3cdc9;display:flex;align-items:center;justify-content:center;flex:none}
.dz-fopt.on .dz-box{background:var(--gold);border-color:var(--gold);color:#fff}
.dz-foot{margin-top:30px;border-top:1px solid var(--line);padding-top:14px;text-align:center;font-size:11.5px;color:#8a9893}
.dz-note{font-size:11.5px;color:var(--muted);text-align:center;margin-top:12px}
@keyframes dzFade{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
.dz-ovl{position:fixed;inset:0;z-index:50;display:flex;align-items:flex-start;justify-content:center;padding:28px 16px;overflow-y:auto;
background:rgba(8,22,31,.55);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px);animation:dzOvl .18s ease both}
.dz-modal{position:relative;width:100%;max-width:540px;margin:auto;background:linear-gradient(180deg,#fbf7ec,#fff);
border:1px solid var(--gold);border-radius:18px;box-shadow:0 34px 80px -26px rgba(8,22,31,.65);overflow:hidden;
animation:dzPop .22s cubic-bezier(.2,.8,.25,1) both}
.dz-mhead{display:flex;align-items:center;gap:9px;padding:15px 18px;border-bottom:1px solid rgba(169,128,42,.25);font-weight:600;
background:linear-gradient(180deg,#f5ead0,#fbf7ec)}
.dz-mhead svg.lead{color:var(--gold)}
.dz-mclose{margin-left:auto;display:flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:9px;border:1px solid var(--line);background:#fff;color:var(--muted);cursor:pointer;transition:all .15s}
.dz-mclose:hover{color:var(--ink);border-color:#9fb1ac}
.dz-mbody{padding:18px}
.dz-mfoot{display:flex;gap:10px;align-items:center;padding:14px 18px;border-top:1px solid var(--line);background:#fff}
@keyframes dzOvl{from{opacity:0}to{opacity:1}}
@keyframes dzPop{from{opacity:0;transform:translateY(12px) scale(.98)}to{opacity:1;transform:none}}
@media(prefers-reduced-motion:reduce){.dz-row{animation:none}.dz-fill{transition:none}.dz-chip{transition:none}.dz-ovl,.dz-modal{animation:none}}
`;

const EXTRA_CSS = `
.dz-boot{margin-top:40px;padding:28px;border-radius:16px;border:1px solid var(--line);background:var(--card);
color:var(--muted);font-size:14px;display:flex;gap:14px;align-items:flex-start}
.dz-boot.small{margin:0;border:none;padding:22px;font-size:13px}
.dz-boot.err{border-color:rgba(180,67,79,.35);background:rgba(180,67,79,.06);color:#7d2b34}
.dz-boot.err svg{color:#b4434f;flex:none;margin-top:2px}
.dz-keytrunc{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dz-rp{font-size:11px;color:#9fb4b1;letter-spacing:.02em}
.dz-audit{margin-top:12px;padding:10px 14px;border-radius:11px;font-size:13px;border:1px solid}
.dz-audit.good{border-color:rgba(44,122,88,.35);background:var(--greensoft);color:#1e5c40}
.dz-audit.bad{border-color:rgba(180,67,79,.4);background:rgba(180,67,79,.08);color:#8a3038}
.dz-credtop.refused{background:linear-gradient(135deg,#5a2230,#3a1620)}
.dz-refused{padding:22px 20px}
.dz-refused code{font-family:'JetBrains Mono',monospace;font-size:12px;color:#8a3038;
background:rgba(180,67,79,.1);border:1px solid rgba(180,67,79,.3);border-radius:6px;padding:3px 8px}
.dz-refused p{font-size:13.5px;color:var(--ink);margin:12px 0 0;line-height:1.55}
.dz-refused .dz-refnote{font-size:12.5px;color:var(--muted)}
.dz-derived{margin-left:7px;font-size:9px;font-weight:700;letter-spacing:.08em;color:var(--gold);
border:1px solid rgba(169,128,42,.45);background:rgba(169,128,42,.1);border-radius:999px;padding:1px 6px}
.dz-sens{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted)}
.dz-formerr{margin-top:14px;padding:10px 12px;border-radius:9px;font-size:12.5px;display:flex;gap:8px;
align-items:flex-start;border:1px solid rgba(180,67,79,.35);background:rgba(180,67,79,.07);color:#8a3038}
.dz-formerr svg{flex:none;margin-top:1px}
.dz-200.bad{background:rgba(180,67,79,.15);color:#f0b0a8;border-color:rgba(240,176,168,.4)}
`;

const TIER = {
  Critical: { c: "#b4434f", b: "rgba(180,67,79,.4)", bg: "rgba(180,67,79,.12)" },
  High: { c: "#b07d22", b: "rgba(176,125,34,.45)", bg: "rgba(176,125,34,.14)" },
  Standard: { c: "#3a86c4", b: "rgba(58,134,196,.4)", bg: "rgba(58,134,196,.14)" },
  Variable: { c: "#8a6bc9", b: "rgba(138,107,201,.4)", bg: "rgba(138,107,201,.14)" },
  Minimal: { c: "#c9d2cf", b: "rgba(255,255,255,.3)", bg: "rgba(255,255,255,.1)" },
  Public: { c: "#7fd6ad", b: "rgba(127,214,173,.4)", bg: "rgba(127,214,173,.14)" },
  Administrative: { c: "#9fb4b1", b: "rgba(159,180,177,.4)", bg: "rgba(159,180,177,.14)" },
  Custom: { c: "#e7c98a", b: "rgba(231,201,138,.5)", bg: "rgba(231,201,138,.16)" },
  Unprotected: { c: "#f0b0a8", b: "rgba(240,176,168,.5)", bg: "rgba(240,176,168,.16)" },
};

const PIPE = [
  { Icon: UserRound, label: "Identity" },
  { Icon: KeyRound, label: "Signed key" },
  { Icon: ShieldCheck, label: "Verify" },
  { Icon: Filter, label: "Project" },
  { Icon: Braces, label: "Response" },
];

export default function DalanIDPrototype() {
  const [schema, setSchema] = useState([]);
  const [contexts, setContexts] = useState([]);
  const [disclosures, setDisclosures] = useState({});
  const [booting, setBooting] = useState(true);
  const [bootError, setBootError] = useState(null);
  const [audit, setAudit] = useState(null);

  const [activeSlug, setActiveSlug] = useState("immigration");
  const [mode, setMode] = useState("explore");
  const [cmpLeft, setCmpLeft] = useState("immigration");
  const [cmpRight, setCmpRight] = useState("social");

  const [showForm, setShowForm] = useState(false);
  const [fName, setFName] = useState("");
  const [fPurpose, setFPurpose] = useState("");
  const [fTier, setFTier] = useState("Standard");
  const [fFields, setFFields] = useState([]);
  const [formError, setFormError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const all = [FULL_CONTEXT, ...contexts];
  const lookup = useCallback(
    (slug) => all.find((c) => c.slug === slug) || FULL_CONTEXT,
    [contexts],
  );

  /** Fetch a disclosure once and cache it. Refusals are cached too, because a
   *  401 is a result the interface should display, not an error to retry. */
  const ensure = useCallback(async (slug) => {
    if (!slug || disclosures[slug]) return;
    const context = all.find((c) => c.slug === slug);
    if (!context) return;
    setDisclosures((prev) => ({ ...prev, [slug]: { loading: true } }));
    try {
      const body = await api.discloseUnder(CITIZEN, context);
      setDisclosures((prev) => ({ ...prev, [slug]: body }));
    } catch (error) {
      setDisclosures((prev) => ({
        ...prev,
        [slug]: {
          refused: true,
          reason: error.body?.reason || "UNAVAILABLE",
          detail: error.message,
        },
      }));
    }
  }, [disclosures, contexts]);

  useEffect(() => {
    let cancelled = false;
    api.listContexts()
      .then((data) => {
        if (cancelled) return;
        setSchema(data.schema);
        setContexts(data.contexts.filter((c) => c.field_count > 0));
        setBooting(false);
      })
      .catch((error) => {
        if (cancelled) return;
        setBootError(error.message);
        setBooting(false);
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (booting || bootError) return;
    if (mode === "explore") ensure(activeSlug);
    else { ensure(cmpLeft); ensure(cmpRight); }
  }, [booting, bootError, mode, activeSlug, cmpLeft, cmpRight, ensure]);

  useEffect(() => {
    if (!showForm) return;
    const onKey = (e) => { if (e.key === "Escape") setShowForm(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [showForm]);

  async function submitContext() {
    setSubmitting(true);
    setFormError(null);
    const slug = fName.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "").slice(0, 40);
    try {
      // Creating a context does not authorise its use, so the interface makes
      // the second call explicitly. This mirrors the server's separation of
      // defining a purpose from being permitted to act on it.
      const created = await api.createContext({
        slug, name: fName.trim(), tier: fTier,
        purpose: fPurpose.trim(), attributes: fFields,
      });
      await api.grantContext(created.slug, "ministry-health");
      const data = await api.listContexts();
      setContexts(data.contexts.filter((c) => c.field_count > 0));
      setActiveSlug(created.slug);
      setMode("explore");
      setShowForm(false);
      setFName(""); setFPurpose(""); setFFields([]); setFTier("Standard");
    } catch (error) {
      const detail = error.body?.detail;
      setFormError(
        typeof detail === "object" && detail
          ? Object.values(detail).flat().join(" ")
          : error.message,
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function runAuditCheck() {
    setAudit({ loading: true });
    try { setAudit(await api.verifyAudit()); }
    catch (error) { setAudit({ intact: false, detail: error.message }); }
  }

  if (booting) {
    return (
      <div className="dz"><style>{CSS}{EXTRA_CSS}</style>
        <div className="dz-wrap"><div className="dz-boot">
          Contacting the DalanID service…
        </div></div>
      </div>
    );
  }

  if (bootError) {
    return (
      <div className="dz"><style>{CSS}{EXTRA_CSS}</style>
        <div className="dz-wrap"><div className="dz-boot err">
          <ShieldAlert size={20} />
          <div>
            <b>The API is not reachable.</b>
            <div style={{ marginTop: 6, fontSize: 13 }}>{bootError}</div>
            <div style={{ marginTop: 10, fontSize: 12.5, opacity: .8 }}>
              Start it with <code>python manage.py runserver</code>, then reload.
            </div>
          </div>
        </div></div>
      </div>
    );
  }

  const active = lookup(activeSlug);
  const ActiveIcon = CTX_ICONS[active.slug] || Layers;
  const activeBody = disclosures[activeSlug];

  return (
    <div className="dz">
      <style>{CSS}{EXTRA_CSS}</style>
      <div className="dz-wrap">

        <header className="dz-head">
          <div className="dz-htop">
            <div className="dz-seal"><ShieldCheck size={24} /></div>
            <div style={{ minWidth: 0 }}>
              <h1 className="dz-title">DalanID</h1>
              <div className="dz-sub">Contextual profile disclosure · one identity, many minimal views</div>
            </div>
            <span className="dz-badge">Live API · synthetic data</span>
          </div>
          <p className="dz-lede">
            DalanID separates a citizen&apos;s core identity from the disclosure of their profile. Every request carries a
            signed Context-Key naming a purpose; the service verifies it and returns only the fields that purpose
            legitimately needs. Nothing below is computed in the browser.
          </p>
          <div className="dz-pipe">
            {PIPE.map((s, i) => (
              <React.Fragment key={s.label}>
                <span className="dz-step"><s.Icon size={15} /><b>{s.label}</b></span>
                {i < PIPE.length - 1 && <span className="dz-arrow">→</span>}
              </React.Fragment>
            ))}
          </div>
          <div className="dz-keyrow">
            <span>Active Context-Key</span>
            <code className="dz-key dz-keytrunc">
              {activeBody?.context_key
                ? `${activeBody.context_key.slice(0, 38)}…`
                : active.slug === "__full__" ? "ROOT · no key" : "—"}
            </code>
            {activeBody?.relying_party && (
              <span className="dz-rp">signed by {activeBody.relying_party}</span>
            )}
          </div>
        </header>

        <div className="dz-secrow">
          <span className="dz-eyebrow">Choose a context</span>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="dz-btn ghost" onClick={runAuditCheck}>
              <Link2 size={15} /> Verify audit chain
            </button>
            <button className={`dz-btn ghost ${mode === "compare" ? "on" : ""}`}
                    onClick={() => setMode(mode === "compare" ? "explore" : "compare")}>
              <GitCompare size={15} /> Compare
            </button>
          </div>
        </div>

        {audit && (
          <div className={`dz-audit ${audit.intact === false ? "bad" : "good"}`}>
            {audit.loading ? "Verifying the disclosure log…" : (
              <>
                <b>{audit.intact ? "Chain intact" : "Chain broken"}</b>
                {" · "}{audit.entries ?? 0} entries
                {audit.broken_at_sequence ? ` · first break at #${audit.broken_at_sequence}` : ""}
                {" · "}{audit.detail}
              </>
            )}
          </div>
        )}

        <div className="dz-ctxbar">
          <div className="dz-selwrap">
            <ActiveIcon size={16} className="dz-sellead" />
            <select className="dz-ctxsel" value={mode === "explore" ? activeSlug : ""}
                    onChange={(e) => { setActiveSlug(e.target.value); setMode("explore"); }}>
              {mode !== "explore" && <option value="" disabled>Select a context to view…</option>}
              {all.map((c) => (
                <option key={c.slug} value={c.slug}>{c.name} · {c.tier}</option>
              ))}
            </select>
            <ChevronDown size={16} className="dz-selchev" />
          </div>
          <button className="dz-btn ghost" onClick={() => setShowForm((v) => !v)}>
            <Plus size={15} /> New context
          </button>
        </div>

        {showForm && (
          <div className="dz-ovl" onClick={() => setShowForm(false)}>
            <div className="dz-modal" role="dialog" aria-modal="true"
                 aria-label="Define a new context" onClick={(e) => e.stopPropagation()}>
              <div className="dz-mhead">
                <Layers size={17} className="lead" /> Define a new context
                <button className="dz-mclose" onClick={() => setShowForm(false)} aria-label="Close">
                  <X size={16} />
                </button>
              </div>
              <div className="dz-mbody">
                <div className="dz-formnote">
                  This posts to a role-gated endpoint. The request is signed as the Ministry of
                  Health, which holds the <code>context-administration</code> grant. The server
                  refuses contexts that are too broad or too sensitive, so extensibility cannot
                  be used to rebuild the unprotected record.
                </div>
                <div className="dz-fgrid">
                  <div>
                    <label className="dz-flabel">Context name</label>
                    <input className="dz-input" value={fName} autoFocus
                           onChange={(e) => setFName(e.target.value)}
                           placeholder="e.g. Library membership" />
                  </div>
                  <div>
                    <label className="dz-flabel">Sensitivity tier</label>
                    <select className="dz-select" value={fTier}
                            onChange={(e) => setFTier(e.target.value)}>
                      {["Minimal", "Standard", "High", "Critical"].map((t) => <option key={t}>{t}</option>)}
                    </select>
                  </div>
                </div>
                <label className="dz-flabel" style={{ marginTop: 14 }}>
                  Declared purpose <span style={{ opacity: .6 }}>(required, 20 characters minimum)</span>
                </label>
                <input className="dz-input" value={fPurpose}
                       onChange={(e) => setFPurpose(e.target.value)}
                       placeholder="Why this context needs to exist" />
                <label className="dz-flabel" style={{ marginTop: 14 }}>
                  Fields this context may disclose
                </label>
                <div className="dz-fields">
                  {schema.map((f) => {
                    const on = fFields.includes(f.code);
                    return (
                      <button key={f.code} className={`dz-fopt ${on ? "on" : ""}`}
                              onClick={() => setFFields((p) => p.includes(f.code)
                                ? p.filter((x) => x !== f.code) : [...p, f.code])}>
                        <span className="dz-box">{on && <Check size={12} />}</span>
                        {f.label}
                        <span className="dz-sens">s{f.sensitivity}</span>
                      </button>
                    );
                  })}
                </div>
                {formError && <div className="dz-formerr"><ShieldAlert size={14} /> {formError}</div>}
              </div>
              <div className="dz-mfoot">
                <button className="dz-btn gold" onClick={submitContext}
                        disabled={submitting || !fName.trim() || fFields.length === 0}>
                  <KeyRound size={15} /> {submitting ? "Creating…" : "Create context & query"}
                </button>
                <button className="dz-btn ghost" onClick={() => setShowForm(false)}>Cancel</button>
              </div>
            </div>
          </div>
        )}

        <div style={{ marginTop: 18 }}>
          {mode === "explore" ? (
            <div className="dz-grid">
              <Credential meta={active} body={activeBody} schema={schema} />
              <JsonPanel body={activeBody} />
            </div>
          ) : (
            <div>
              <div className="dz-pickrow">
                <select className="dz-select" value={cmpLeft}
                        onChange={(e) => setCmpLeft(e.target.value)}>
                  {all.map((c) => <option key={c.slug} value={c.slug}>{c.name}</option>)}
                </select>
                <select className="dz-select" value={cmpRight}
                        onChange={(e) => setCmpRight(e.target.value)}>
                  {all.map((c) => <option key={c.slug} value={c.slug}>{c.name}</option>)}
                </select>
              </div>
              <div className="dz-cmpgrid">
                <Credential meta={lookup(cmpLeft)} body={disclosures[cmpLeft]} schema={schema} />
                <Credential meta={lookup(cmpRight)} body={disclosures[cmpRight]} schema={schema} />
              </div>
              <p className="dz-note">
                Same citizen, same database record — only the context differs. Both panels are
                separate authenticated requests to the API.
              </p>
            </div>
          )}
        </div>

        <div className="dz-foot">
          DalanID · field-level data minimisation enforced server-side · all data fictional
        </div>
      </div>
    </div>
  );
}

function Credential({ meta, body, schema }) {
  const t = TIER[meta.tier] || TIER.Minimal;
  const CtxIcon = CTX_ICONS[meta.slug] || Layers;
  const total = schema.length || 8;

  if (!body || body.loading) {
    return (
      <div className="dz-cred"><div className="dz-credtop">
        <div className="row1"><CtxIcon size={17} /><span className="nm">{meta.name}</span></div>
      </div><div className="dz-boot small">Requesting disclosure…</div></div>
    );
  }

  if (body.refused) {
    return (
      <div className="dz-cred"><div className="dz-credtop refused">
        <div className="row1">
          <ShieldAlert size={17} /><span className="nm">{meta.name}</span>
          <span className="dz-tier" style={{ color: "#f0b0a8", borderColor: "rgba(240,176,168,.5)", background: "rgba(240,176,168,.16)" }}>
            Refused
          </span>
        </div>
      </div>
      <div className="dz-refused">
        <code>{body.reason}</code>
        <p>{body.detail}</p>
        <p className="dz-refnote">
          The server declined this request. No fields were released, and the refusal was written
          to the audit chain.
        </p>
      </div></div>
    );
  }

  const disclosed = body.disclosed || {};
  const derived = new Set(body.derived_fields || []);
  const shown = Object.keys(disclosed).length;
  const pct = Math.round((shown / total) * 100);

  const holderName = disclosed.legal_name || disclosed.nickname || "Identity protected";
  const holderMeta = disclosed.legal_name ? "Verified citizen"
    : disclosed.nickname ? "Public handle only" : "No legal identifiers disclosed";
  const named = Boolean(disclosed.legal_name || disclosed.nickname);

  return (
    <div className="dz-cred">
      <div className={`dz-credtop ${meta.slug === "__full__" ? "full" : ""}`}>
        <div className="row1">
          <CtxIcon size={17} />
          <span className="nm">{meta.name}</span>
          <span className="dz-tier" style={{ color: t.c, borderColor: t.b, background: t.bg }}>
            {meta.tier}
          </span>
          <span className="dz-200" style={{ marginLeft: "auto" }}>200 OK</span>
        </div>
      </div>
      <div className="dz-holder">
        <div className={`dz-av ${named ? "" : "protected"}`}>
          {named ? holderName.charAt(0).toUpperCase() : <UserRound size={30} />}
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="dz-hname">{holderName}</div>
          <div className="dz-hmeta">{holderMeta}</div>
        </div>
        <ScanLine size={20} color="#c2ccc8" style={{ marginLeft: "auto" }} />
      </div>
      <div className="dz-meter">
        <div className="dz-meterhead">
          <span>Fields disclosed</span><b>{shown} of {total}</b>
        </div>
        <div className="dz-track">
          <div className="dz-fill" style={{
            width: pct + "%",
            background: shown === total ? "#b4434f" : "linear-gradient(90deg,#2C7A58,#3da176)",
          }} />
        </div>
      </div>
      <div className="dz-rows" key={meta.slug}>
        {schema.map((f, i) => {
          const on = Object.prototype.hasOwnProperty.call(disclosed, f.code);
          const FieldIcon = ATTR_ICONS[f.code] || Layers;
          return (
            <div key={f.code} className={`dz-row ${on ? "on" : "off"}`}
                 style={{ animationDelay: i * 28 + "ms" }}>
              <span className="dz-ricon">{on ? <FieldIcon size={16} /> : <Lock size={14} />}</span>
              <div className="dz-rmid">
                <div className="dz-rlabel">
                  {f.label}
                  {on && derived.has(f.code) && <span className="dz-derived">derived</span>}
                </div>
                {on ? <div className="dz-rval">{disclosed[f.code]}</div>
                  : <div className="dz-redact"><span><Lock size={9} /> Withheld</span></div>}
              </div>
              {on ? <Eye size={15} className="dz-rtag" style={{ color: "var(--green)" }} />
                : <span className="dz-rtag">hidden</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function JsonPanel({ body }) {
  if (!body || body.loading) {
    return <div className="dz-json"><div className="dz-jtop"><Braces size={15} /> API response</div>
      <pre>Awaiting response…</pre></div>;
  }
  const status = body.refused ? "401 Unauthorized" : "200 OK";
  const shown = body.refused
    ? { error: "context_key_refused", reason: body.reason, detail: body.detail }
    : { ...body };
  if (shown.context_key) shown.context_key = shown.context_key.slice(0, 24) + "…";
  return (
    <div className="dz-json">
      <div className="dz-jtop">
        <Braces size={15} /> API response
        <span className={`dz-200 ${body.refused ? "bad" : ""}`}>{status}</span>
      </div>
      <pre>{JSON.stringify(shown, null, 2)}</pre>
      <div className="dz-jnote">
        Returned verbatim by Django. Fields outside the context are never serialised —
        minimisation happens before the response is built.
      </div>
    </div>
  );
}
