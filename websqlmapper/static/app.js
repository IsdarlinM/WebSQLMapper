"use strict";
(()=>{
  const queue=["/static/app-v042.js","/static/ui-core.js","/static/ui-enhance.js"];
  const load=(i)=>{if(i>=queue.length)return;const s=document.createElement("script");s.src=queue[i];s.onload=()=>load(i+1);s.onerror=()=>console.error(`WebSQLMapper UI module failed: ${queue[i]}`);document.head.appendChild(s);};
  load(0);
})();
