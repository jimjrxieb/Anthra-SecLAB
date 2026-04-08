import Hero from '../components/Hero.tsx';
import PortfolioBuild from '../components/PortfolioBuild.tsx';
import CurrentVenture from '../components/CurrentVenture.tsx';

export default function Landing() {
  return (
    <div
      className="min-h-screen bg-gradient-to-br from-ink via-ink to-crystal-900"
      data-dev="landing"
    >
      {/* Hero Section - Full Width */}
      <Hero />

      {/* Welcome + About - Centralized */}
      <div className="relative z-10 px-6 pb-6">
        <div className="max-w-7xl mx-auto">
          <div className="bg-gradient-to-br from-jade-500/10 to-crystal-500/10 backdrop-blur-sm rounded-2xl border border-jade-500/30 p-8 text-center">
            <h2 className="text-2xl font-bold text-white mb-4">
              Secure → Optimize → Outcome
            </h2>
            <p className="text-text-secondary text-sm leading-relaxed max-w-3xl mx-auto mb-4">
              I secure infrastructure before optimizing it. SAST to runtime, application code to cluster config —{' '}
              <span className="text-white font-medium">GP-Copilot</span> automates the full engagement cycle so
              platform engineers deliver{' '}
              <span className="text-crystal-400 font-medium">senior-level outcomes</span> without senior-level headcount.
            </p>
            <p className="text-text-secondary text-sm leading-relaxed max-w-3xl mx-auto mb-4">
              The result: a Kubernetes cluster that went from{' '}
              <span className="text-crystal-400 font-medium">34% to 71.5% compliance</span>,{' '}
              <span className="text-crystal-400 font-medium">264 findings</span> triaged automatically, and{' '}
              <span className="text-crystal-400 font-medium">~$13K/quarter</span> in manual labor eliminated —
              built and operated by one engineer.
            </p>
            <p className="text-text-secondary text-sm leading-relaxed max-w-3xl mx-auto mb-4">
              This portfolio is the proof. A production app deployed via{' '}
              <span className="text-crystal-400 font-medium">ArgoCD GitOps</span>, secured by an 8-scanner CI pipeline.
              On the left, the work. On the right, the AI that multiplies it. Below,{' '}
              <span className="text-crystal-400 font-medium">Sheyla</span> — ask her anything.
            </p>
          </div>
        </div>
      </div>

      {/* Two Column Layout */}
      <div className="relative z-10 px-6 pb-6">
        <div className="max-w-7xl mx-auto">
          <div className="grid lg:grid-cols-[55%_45%] gap-8">
            {/* Left Column - Platform Engineering (the core work) */}
            <CurrentVenture />

            {/* Right Column - AI & Automation (includes Sheyla chatbox) */}
            <PortfolioBuild />
          </div>
        </div>
      </div>

      {/* Background Effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-crystal-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-jade-500/10 rounded-full blur-2xl"></div>
      </div>
    </div>
  );
}
