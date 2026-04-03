import React from "react";
import LetterGlitch from "../components/LetterGlitch";
import UploadFile from "../components/UploadFile";

const Home = () => {
  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center p-6 font-sans bg-black overflow-hidden">
      
      {/* Background Layer: Your original dark/neon glitch colors */}
      <div className="absolute inset-0 z-0 pointer-events-none">
        <LetterGlitch
          glitchColors={["#2b4539", "#61dca3", "#61b3dc"]}
          glitchSpeed={50}
          outerVignette={true}
        />
      </div>

      {/* Foreground Content */}
      <div className="relative z-10 w-full flex flex-col items-center">
        
        <div className="text-center mb-10">
          <h1 className="text-4xl font-bold text-white tracking-tight mb-3 drop-shadow-lg">
            Network Threat <span className="text-blue-400">Intelligence</span>
          </h1>
          <p className="text-slate-300 max-w-lg mx-auto drop-shadow-md font-medium">
            Upload a raw packet capture to passively discover assets, extract
            service banners, and correlate vulnerabilities against the NVD
            database.
          </p>
        </div>

        <UploadFile />

      </div>
    </div>
  );
};

export default Home;