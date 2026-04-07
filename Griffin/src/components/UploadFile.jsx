import React, { useState } from "react";
import { useNavigate } from "react-router-dom"; // Import the navigation hook
import ClickSpark from "./ClickSpark";

const UploadFile = () => {
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate(); // Initialize the router

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setError(null);

    if (selectedFile) {
      // UPGRADED: Now accepts .nmap plain text files as well
      if (
        selectedFile.name.endsWith(".pcap") ||
        selectedFile.name.endsWith(".pcapng") ||
        selectedFile.name.endsWith(".xml") ||
        selectedFile.name.endsWith(".nmap")
      ) {
        setFile(selectedFile);
      } else {
        setFile(null);
        setError("Invalid file type. Please upload a .pcap, .pcapng, .xml, or .nmap file.");
      }
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setError(null);

    // Prepare the file to be sent via HTTP POST
    const formData = new FormData();
    formData.append("file", file);

    try {
      // Send the file to your FastAPI backend
      const response = await fetch("http://127.0.0.1:8000/api/analyze-pcap", {
        method: "POST",
        body: formData, // The browser automatically sets the correct multipart/form-data headers
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Analysis failed on the server.");
      }

      // Parse the successful response from Python
      const data = await response.json();
      
      // Route the user to the Dashboard and pass the backend data securely
      navigate("/dashboard", { state: { results: data } });

    } catch (err) {
      setError(err.message || "Failed to connect to the analysis engine. Is Python running?");
      setIsUploading(false); // Only stop the spinner if there is an error
    } 
  };

  return (
    <div className="bg-slate-900/80 backdrop-blur-md rounded-xl shadow-2xl shadow-black/50 p-8 w-full max-w-2xl border border-slate-700/50">
      
      {/* Upload Dropzone */}
      <label
        htmlFor="file-upload"
        className={`flex flex-col items-center justify-center w-full h-64 border-2 border-dashed rounded-lg cursor-pointer transition-all duration-300
          ${
            file
              ? "border-blue-500 bg-slate-800/80"
              : "border-slate-500 hover:border-blue-400 hover:bg-slate-800/50"
          }`}
      >
        <div className="flex flex-col items-center justify-center pt-5 pb-6 text-slate-300">
          <svg aria-hidden="true" className="w-12 h-12 mb-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
          </svg>

          {file ? (
            <p className="mb-2 text-lg font-semibold text-blue-400">
              {file.name}
            </p>
          ) : (
            <>
              <p className="mb-2 text-sm font-semibold">
                Click to upload or drag and drop
              </p>
              <p className="text-xs text-slate-400 mt-1">
                .PCAP, .XML, or .NMAP formats (Max 50MB)
              </p>
            </>
          )}
        </div>
        <input
          id="file-upload"
          type="file"
          className="hidden"
          accept=".pcap,.pcapng,.xml,.nmap"
          onChange={handleFileChange}
        />
      </label>

      {/* Error Message Display */}
      {error && (
        <div className="mt-4 p-3 bg-red-900/80 border border-red-500 rounded text-red-200 text-sm text-center font-medium">
          {error}
        </div>
      )}

      {/* Action Button wrapped in ClickSpark */}
      <div className="mt-8 flex justify-center">
        <ClickSpark
          sparkColor="#fff"
          sparkSize={12}
          sparkRadius={20}
          sparkCount={8}
          duration={500}
        >
          <button
            onClick={handleUpload}
            disabled={!file || isUploading}
            className={`px-8 py-3 rounded-lg font-bold text-white transition-all duration-200 relative z-20
              ${
                !file || isUploading
                  ? "bg-slate-700/80 cursor-not-allowed opacity-50"
                  : "bg-blue-600 hover:bg-blue-500 shadow-lg shadow-blue-900/50 hover:-translate-y-0.5"
              }`}
          >
            {isUploading ? (
              <span className="flex items-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Running Threat Correlation...
              </span>
            ) : (
              "Run Threat Analysis"
            )}
          </button>
        </ClickSpark>
      </div>
    </div>
  );
};

export default UploadFile;