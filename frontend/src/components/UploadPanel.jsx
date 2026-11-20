import { useRef, useState } from "react";

export default function UploadPanel({ t, onFile, onSample, samples, loading }) {
  const inputRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  function handleDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFile(file);
  }

  return (
    <div className="space-y-4">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-xl border-2 border-dashed p-10 text-center transition-colors ${
          dragOver ? "border-violet-400 bg-violet-950/30" : "border-slate-700 bg-slate-900/50"
        }`}
      >
        <p className="text-slate-300">{loading ? t.analyzing : t.dropzone}</p>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onFile(file);
          }}
        />
      </div>

      {samples?.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-slate-400">{t.demoSamples}:</span>
          {samples.map((name) => (
            <button
              key={name}
              onClick={() => onSample(name)}
              disabled={loading}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-slate-200 hover:bg-slate-700 disabled:opacity-50"
            >
              {name.includes("clean") ? `✓ ${t.clean}` : `⚠ ${t.suspicious}`}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
