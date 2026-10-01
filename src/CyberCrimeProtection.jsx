import { useState } from "react";
import "./CyberCrimeProtection.css";

function CyberCrimeProtection() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeThreat = () => {
    if (!input.trim()) return;

    setLoading(true);
    setResult(null);

    setTimeout(() => {
      const suspiciousWords = [
        "login",
        "verify",
        "password",
        "free",
        "winner",
        "prize",
        "account",
        "confirm",
        "bank",
        "urgent",
      ];

      const text = input.toLowerCase();

      const detected = suspiciousWords.filter((word) =>
        text.includes(word)
      );

      let level = "LOW";
      let score = 15;

      if (detected.length >= 2) {
        level = "MEDIUM";
        score = 55;
      }

      if (detected.length >= 4) {
        level = "HIGH";
        score = 85;
      }

      setResult({
        level,
        score,
        detected,
        message:
          level === "HIGH"
            ? "Shubhali belgilar ko‘p aniqlandi."
            : level === "MEDIUM"
            ? "Bir nechta xavfli belgilar aniqlandi."
            : "Jiddiy xavf belgisi aniqlanmadi.",
      });

      setLoading(false);
    }, 1500);
  };

  return (
    <div className="cybercrime-page">
      <div className="cybercrime-header">
        <div>
          <h1>Cybercrime Protection</h1>
          <p>
            Kiberjinoyat va firibgarlik alomatlarini aniqlash tizimi
          </p>
        </div>

        <div className="protection-status">
          <span></span>
          Protection Active
        </div>
      </div>

      <div className="protection-grid">
        <div className="protection-card">
          <h2>🔍 Threat Analyzer</h2>

          <p>
            Shubhali URL, SMS, email yoki xabarni kiriting.
          </p>

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Masalan: Your account is locked. Verify your password..."
          />

          <button
            onClick={analyzeThreat}
            disabled={loading}
          >
            {loading ? "Analyzing..." : "Analyze Threat"}
          </button>
        </div>

        <div className="protection-card result-card">
          <h2>🛡️ Analysis Result</h2>

          {!result && !loading && (
            <div className="empty-result">
              <div className="shield">🛡️</div>
              <p>Tekshiruv natijasi shu yerda chiqadi</p>
            </div>
          )}

          {loading && (
            <div className="scanning">
              <div className="spinner"></div>
              <p>CyberGuard AI tahlil qilmoqda...</p>
            </div>
          )}

          {result && (
            <div className="analysis-result">
              <div className={`risk-level ${result.level.toLowerCase()}`}>
                {result.level}
              </div>

              <div className="risk-score">
                <strong>{result.score}%</strong>
                <span>Threat Score</span>
              </div>

              <p>{result.message}</p>

              {result.detected.length > 0 && (
                <div className="detected">
                  <h3>Detected indicators</h3>

                  {result.detected.map((item, index) => (
                    <div className="indicator" key={index}>
                      ⚠️ {item}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default CyberCrimeProtection;