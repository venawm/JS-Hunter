// 'use client';

// import { motion } from "framer-motion";
// import { ChevronRight, FileCode } from "lucide-react";
// import { GlassCard } from "@/components/ui/card-glass";
// import { SeverityBadge } from "@/components/ui/badge-severity";
// import { Finding } from "@/lib/types";

// // Mock Data
// const FINDINGS: Finding[] = [
//   { id: 1, type: "VULN_SQL_INJECTION", severity: "CRITICAL", evidence: "SELECT * FROM users WHERE id = " + "${input}", line: 42, file: "auth/login.js", timestamp: "Now" },
//   { id: 2, type: "SECRET_AWS_KEY", severity: "CRITICAL", evidence: "AKIAIOSFODNN7EXAMPLE", line: 12, file: "config/aws.js", timestamp: "2m ago" },
//   { id: 3, type: "VULN_XSS_REFLECTED", severity: "HIGH", evidence: "innerHTML = query.param", line: 89, file: "views/profile.js", timestamp: "5m ago" },
//   { id: 4, type: "SHADOW_API", severity: "LOW", evidence: "/api/internal/v1/admin", line: 202, file: "api/routes.js", timestamp: "12m ago" },
// ];

// export function FindingsFeed() {
//   return (
//     <GlassCard className="p-0 overflow-hidden min-h-[500px]">
//       <div className="p-4 border-b border-white/5 flex items-center justify-between bg-zinc-900/30">
//         <h3 className="font-semibold text-zinc-200 flex items-center gap-2">
//           <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse"></span>
//           Live Intelligence Feed
//         </h3>
//         <span className="text-xs text-zinc-500 font-mono">SYNCED</span>
//       </div>
      
//       <div className="divide-y divide-white/5">
//         {FINDINGS.map((finding, i) => (
//           <motion.div
//             key={finding.id}
//             initial={{ opacity: 0, x: -10 }}
//             animate={{ opacity: 1, x: 0 }}
//             transition={{ delay: i * 0.1 }}
//             className="group p-4 hover:bg-white/[0.02] cursor-pointer transition-colors"
//           >
//             <div className="flex items-start justify-between">
//               <div className="flex gap-4">
//                 <div className="mt-1">
//                   <SeverityBadge level={finding.severity} />
//                 </div>
//                 <div>
//                   <h4 className="text-sm font-bold text-zinc-200 group-hover:text-red-400 transition-colors font-mono">
//                     {finding.type}
//                   </h4>
//                   <p className="text-xs text-zinc-500 mt-1 font-mono flex items-center gap-2">
//                     <FileCode className="h-3 w-3" />
//                     {finding.file}:{finding.line}
//                   </p>
//                   <code className="block mt-2 text-[10px] text-zinc-400 bg-black/40 px-2 py-1 rounded border border-white/5 w-fit">
//                     {finding.evidence}
//                   </code>
//                 </div>
//               </div>
//               <ChevronRight className="h-4 w-4 text-zinc-700 group-hover:text-zinc-400 transition-colors" />
//             </div>
//           </motion.div>
//         ))}
//       </div>
//     </GlassCard>
//   );
// }