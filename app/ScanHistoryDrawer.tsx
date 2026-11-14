"use client";

import type { AuditReport } from "./api/audit/route";
import { useAuth } from "./context/AuthContext";


type Props = {
  playSound: (type: "click" | "scanStart" | "success" | "error") => void;
  onSelectReport: (report: AuditReport) => void;
  onClearHistory: () => void;
};

export default function ScanHistoryDrawer({
  playSound,
  onSelectReport,
  onClearHistory,
}: Props) {
  const {
    isHistoryOpen,
    setIsHistoryOpen,
    scanHistory,
  } = useAuth();

  if (!isHistoryOpen) return null;

  const closeDrawer = () => {
    playSound("click");
    setIsHistoryOpen(false);
  };

  return (
    <div
      className="drawer-backdrop open"
      id="historyDrawer"
      onClick={closeDrawer}
    >
      <div
        className="drawer-panel"
        style={{ transform: "translateX(0)" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="drawer-header">
          <div>
            <h3
              style={{
                fontSize: "1.3rem",
                fontWeight: 800,
                color: "var(--text-primary)",
                fontFamily: "var(--font-heading)",
              }}
            >
              Audit History
            </h3>

            <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              Stored locally on this workstation
            </p>
          </div>

          <button
            className="modal-close-btn"
            style={{ position: "static" }}
            onClick={closeDrawer}
          >
            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="18" x2="18" y2="6" />
            </svg>
          </button>
        </div>

        <div className="drawer-list" id="historyList">
          {scanHistory.length === 0 ? (
            <div
              style={{
                textAlign: "center",
                padding: "2rem 0",
                color: "var(--text-muted)",
              }}
            >
              No scan history yet.
            </div>
          ) : (
            scanHistory.map((item, idx) => (
              <div
                key={`${item.target}-${item.timestamp}-${idx}`}
                className="drawer-item"
                onClick={() => {
                  playSound("click");
                  onSelectReport(item);
                  setIsHistoryOpen(false);
                }}
              >
                <div>
                  <div
                    style={{
                      fontWeight: 700,
                      color: "var(--text-primary)",
                      fontSize: "0.95rem",
                      fontFamily: "var(--font-heading)",
                    }}
                  >
                    {item.target}
                  </div>

                  <div
                    style={{
                      fontSize: "0.75rem",
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {item.timestamp}
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontWeight: 800,
                      fontSize: "1.1rem",
                      color: item.grade_color,
                    }}
                  >
                    {item.score}
                  </span>

                  <span
                    className="status-badge"
                    style={{
                      background: item.grade_color,
                      color: "#070303",
                      padding: "3px 8px",
                    }}
                  >
                    {item.grade}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        <div
          style={{
            marginTop: "1.5rem",
            display: "flex",
            justifyContent: "flex-end",
          }}
        >
          <button
            className="action-btn"
            onClick={onClearHistory}
            style={{
              color: "var(--danger)",
              borderColor: "rgba(255,34,63,0.35)",
            }}
          >
            Clear History
          </button>
        </div>
      </div>
    </div>
  );
}

